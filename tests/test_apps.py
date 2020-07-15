from unittest import mock

from django.template import TemplateDoesNotExist
from django.test import TestCase

from request_token.apps import ImproperlyConfigured, check_template


class AppTests(TestCase):

    """Tests for request_token.apps functions."""

    @mock.patch("django.template.loader.get_template")
    def test_check_403(self, mock_loader):
        mock_loader.side_effect = TemplateDoesNotExist("Template not found.")
        self.assertRaises(ImproperlyConfigured, check_template, "foo.html")
