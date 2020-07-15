import datetime
from unittest import mock

from django.test import TestCase
from django.utils.timezone import now as tz_now
from jwt.exceptions import MissingRequiredClaimError

from request_token.admin import RequestTokenAdmin, pretty_print
from request_token.models import RequestToken


class AdminTests(TestCase):

    """Admin function tests."""

    def test_pretty_print(self):
        self.assertEqual(pretty_print(None), None)
        self.assertEqual(
            pretty_print({"foo": True}),
            '<pre><code>{<br>&nbsp;&nbsp;&nbsp;&nbsp;"foo":&nbsp;true<br>}</code></pre>',
        )


class RequestTokenAdminTests(TestCase):

    """RequestTokenAdmin class tests."""

    @mock.patch("request_token.models.tz_now")
    def test_is_valid(self, mock_now):
        now = tz_now()
        mock_now.return_value = now
        token = RequestToken()
        admin = RequestTokenAdmin(RequestToken, None)

        token.not_before_time = now + datetime.timedelta(minutes=1)
        self.assertTrue(token.not_before_time > now)
        self.assertFalse(admin.is_valid(token))

        token.not_before_time = None
        token.expiration_time = now - datetime.timedelta(minutes=1)
        self.assertTrue(token.expiration_time < now)
        self.assertFalse(admin.is_valid(token))

        token.expiration_time = None
        token.max_uses = 1
        token.used_to_date = 1
        self.assertFalse(admin.is_valid(token))

        # finally make it valid
        token.max_uses = 10
        self.assertTrue(admin.is_valid(token))

    def test_jwt(self):
        token = RequestToken(id=1, scope="foo").save()
        admin = RequestTokenAdmin(RequestToken, None)
        self.assertEqual(admin.jwt(token), token.jwt())

        token = RequestToken()
        self.assertRaises(MissingRequiredClaimError, token.jwt)
        self.assertEqual(admin.jwt(token), None)

    def test_claims(self):
        token = RequestToken(id=1, scope="foo").save()
        admin = RequestTokenAdmin(RequestToken, None)
        self.assertEqual(admin._claims(token), pretty_print(token.claims))

    def test_parsed(self):
        token = RequestToken(id=1, scope="foo", data='{"foo": true}').save()
        admin = RequestTokenAdmin(RequestToken, None)
        parsed = admin._parsed(token)
        self.assertTrue("header" in parsed)
        self.assertTrue("claims" in parsed)
        self.assertTrue("signature" in parsed)

        # if the token is invalid we get None back
        with mock.patch.object(RequestToken, "jwt", side_effect=Exception()):
            self.assertIsNone(admin._parsed(token))
