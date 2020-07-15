from unittest import mock

from django.test import TestCase

from request_token.settings import JWT_QUERYSTRING_ARG
from request_token.templatetags import request_token_tags


class TemplateTagTests(TestCase):
    def test_request_token_missing(self):
        context = {}
        assert request_token_tags.request_token(context) == ""

    def test_request_token(self):
        context = {"request_token": "foo"}
        assert request_token_tags.request_token(context) == (
            f'<input type="hidden" name="{JWT_QUERYSTRING_ARG}" value="foo">'
        )

    def test_request_token_querystring_missing(self):
        mock_request = mock.Mock()
        mock_request.token = None
        context = {"request": mock_request}
        assert request_token_tags.request_token_querystring(context) == ""

    def test_request_token_querystring(self):
        mock_request = mock.Mock()
        mock_request.token.jwt.return_value = "foo"
        context = {"request": mock_request}
        assert request_token_tags.request_token_querystring(context) == (
            f"?{JWT_QUERYSTRING_ARG}=foo"
        )
