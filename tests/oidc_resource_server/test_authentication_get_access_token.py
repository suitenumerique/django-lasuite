"""Tests for ResourceServerAuthentication.get_access_token method."""

import base64
from unittest.mock import patch

import pytest
from django.test import RequestFactory

from lasuite.oidc_resource_server.authentication import ResourceServerAuthentication


@pytest.fixture(autouse=True)
def common_settings_fixture(settings):
    """Fixture to set up common settings for tests."""
    settings.OIDC_RS_CLIENT_ID = "some_client_id"
    settings.OIDC_RS_CLIENT_SECRET = "some_client_secret"
    settings.OIDC_OP_URL = "https://oidc.example.com"
    settings.OIDC_VERIFY_SSL = False
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://oidc.example.com/introspect"


def test_get_access_token_regular_token():
    """Test retrieving a regular non-encoded token from Authorization header."""
    # Given a request with a regular token
    token = "regular_token_string"
    request = RequestFactory().get("/")
    request.META = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    # When get_access_token is called
    result = ResourceServerAuthentication().get_access_token(request)

    # Then the token is returned as-is
    assert result == token


def test_get_access_token_base64_encoded():
    """Test retrieving a base64-encoded token from Authorization header."""
    # Given a request with a base64-encoded token
    original_token = "original_token_string"
    encoded_token = base64.b64encode(original_token.encode("utf-8")).decode("utf-8")
    request = RequestFactory().get("/")
    request.META = {"HTTP_AUTHORIZATION": f"Bearer {encoded_token}"}

    # When get_access_token is called
    result = ResourceServerAuthentication().get_access_token(request)

    # Then the token is decoded
    assert result == original_token


def test_get_access_token_jwt_like_token():
    """Test retrieving a regular non-encoded JWT like token from Authorization header."""
    # Given a request with a regular token
    token = "eyJhbGciOiJS.eyJhbGciOiJS.UmwJQPqqaK4o"
    request = RequestFactory().get("/")
    request.META = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    # When get_access_token is called
    result = ResourceServerAuthentication().get_access_token(request)

    # Then the token is returned as-is
    assert result == token


def test_get_access_token_invalid_base64():
    """Test retrieving an invalid base64 token returns original token."""
    # Given a request with an invalid base64 token
    invalid_base64 = "invalid-base64!@#$"
    request = RequestFactory().get("/")
    request.META = {"HTTP_AUTHORIZATION": f"Bearer {invalid_base64}"}

    # When get_access_token is called
    result = ResourceServerAuthentication().get_access_token(request)

    # Then the original token is returned
    assert result == invalid_base64


def test_get_access_token_no_auth_header():
    """Test behavior when no Authorization header is present."""
    # Given a request with no Authorization header
    request = RequestFactory().get("/")
    request.META = {}

    assert ResourceServerAuthentication().get_access_token(request) is None


@patch("mozilla_django_oidc.contrib.drf.OIDCAuthentication.get_access_token")
def test_get_access_token_parent_method_called(mock_parent_method):
    """Test that parent class method is called correctly."""
    # Given a request and a mocked parent method
    token = "test_token"
    mock_parent_method.return_value = token
    request = RequestFactory().get("/")

    # When get_access_token is called
    result = ResourceServerAuthentication().get_access_token(request)

    # Then parent method is called with request
    mock_parent_method.assert_called_once_with(request)
    assert result == token
