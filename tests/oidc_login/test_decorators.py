"""Tests for the refresh_oidc_access_token decorator in core app."""

from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory
from django.utils.decorators import method_decorator
from django.views import View

from lasuite.oidc_login.decorators import refresh_oidc_access_token


class RefreshOIDCAccessTokenView(View):
    """
    A Django view that uses the refresh_oidc_access_token decorator to refresh
    the OIDC access token before processing the request.
    """

    @method_decorator(refresh_oidc_access_token)
    def dispatch(self, request, *args, **kwargs):
        """Override the dispatch method to apply the refresh_oidc_access_token decorator."""
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests.

        Returns:
            HttpResponse: A simple HTTP response with "OK" as the content.

        """
        return HttpResponse("OK")


def test_refresh_oidc_access_token_decorator():
    """
    Tests the refresh_oidc_access_token decorator is called on RefreshOIDCAccessTokenView access.
    The test creates a mock request and patches the dispatch method to verify that it is called
    with the correct request object.
    """
    # Create a test request
    factory = RequestFactory()
    request = factory.get("/")

    # Mock the OIDC refresh functionality
    with patch("lasuite.oidc_login.middleware.RefreshOIDCAccessToken.process_request") as mock_refresh:
        # Call the decorated view
        RefreshOIDCAccessTokenView.as_view()(request)

        # Assert that the refresh method was called
        mock_refresh.assert_called_once_with(request)
