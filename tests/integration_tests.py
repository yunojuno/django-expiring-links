from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import Client, TransactionTestCase
from django.urls import reverse

from request_token.models import RequestToken, RequestTokenLog, tz_now
from request_token.settings import JWT_QUERYSTRING_ARG, JWT_SESSION_TOKEN_EXPIRY
from request_token.templatetags.request_token_tags import request_token


def get_url(url_name, token):
    """Helper to format urls with tokens."""
    url = reverse("test_app:%s" % url_name)
    if token:
        url += "?%s=%s" % (JWT_QUERYSTRING_ARG, token.jwt())
    return url


class ViewTests(TransactionTestCase):

    """Test the end-to-end use of tokens.

    These tests specifically confirm the way in which request and session tokens
    deal with repeated requests.

    """

    def setUp(self):
        self.client = Client()
        self.user = get_user_model().objects.create_user("zoidberg")

    def test_request_token(self):
        """Test the request tokens only set the user for a single request."""
        token = RequestToken.objects.create_token(
            scope="foo",
            max_uses=2,
            user=self.user,
            login_mode=RequestToken.LOGIN_MODE_REQUEST,
        )
        response = self.client.get(get_url("decorated", token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request_user, self.user)
        self.assertEqual(RequestTokenLog.objects.count(), 1)

        response = self.client.get(get_url("undecorated", None))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.request_user, AnonymousUser)
        self.assertEqual(RequestTokenLog.objects.count(), 1)

    def test_session_token(self):
        """Test that session tokens set the user for all requests."""
        token = RequestToken.objects.create_token(
            scope="foo",
            max_uses=1,
            user=self.user,
            login_mode=RequestToken.LOGIN_MODE_SESSION,
            expiration_time=(
                datetime.now() + timedelta(minutes=JWT_SESSION_TOKEN_EXPIRY)
            ),
        )

        response = self.client.get(get_url("decorated", token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request_user, self.user)
        self.assertEqual(RequestTokenLog.objects.count(), 1)

        # for a session token, all future requests should also be authenticated
        response = self.client.get(get_url("undecorated", None))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request_user, self.user)
        self.assertEqual(RequestTokenLog.objects.count(), 1)

    def test_get_post_token(self):
        """Test the GET > POST chain."""
        token = RequestToken.objects.create_token(
            scope="bar", login_mode=RequestToken.LOGIN_MODE_NONE, max_uses=100
        )
        # expiry not set - we will do that explicitly in the POST
        self.assertTrue(token.expiration_time is None)
        # this is the output from the {% request_token %} tag
        html = request_token({"request_token": token.jwt()})

        # initial GET - mark token as used, do not expire
        response = self.client.get(get_url("roundtrip", token))
        self.assertContains(response, html, status_code=200)
        token.refresh_from_db()
        self.assertTrue(token.expiration_time is None)
        self.assertEqual(token.used_to_date, 1)

        # now re-post the token to the same URL - equivalent to POSTing the form
        response = self.client.post(
            get_url("roundtrip", None), {JWT_QUERYSTRING_ARG: token.jwt()}
        )
        # 201 is a sentinel status_code so we know that the form has been processed
        self.assertContains(response, "OK", status_code=201)
        token.refresh_from_db()
        # token has been forcibly expired
        self.assertFalse(token.expiration_time is None)
        self.assertTrue(token.expiration_time < tz_now())
        self.assertEqual(token.used_to_date, 2)
