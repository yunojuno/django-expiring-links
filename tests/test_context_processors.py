from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.test import TestCase

from request_token.context_processors import request_token
from request_token.models import RequestToken


@mock.patch.object(RequestToken, "jwt", lambda t: "foo")
class ContextProcessorTests(TestCase):
    def test_request_token_no_token(self):
        request = HttpRequest()
        context = request_token(request)
        with self.assertRaises(ImproperlyConfigured):
            # assert forces evaluation of SimpleLazyObject
            assert context["request_token"]

    def test_request_token(self):
        request = HttpRequest()
        request.token = RequestToken()
        context = request_token(request)
        assert context["request_token"] == request.token.jwt()
