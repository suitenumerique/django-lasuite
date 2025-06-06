"""Test for the Resource Server (RS) clients classes."""

# pylint: disable=W0212

from unittest.mock import MagicMock, patch

import pytest
from joserfc.errors import MissingKeyTypeError
from joserfc.jwk import KeySet, RSAKey
from requests.exceptions import HTTPError

from lasuite.oidc_resource_server.clients import AuthorizationServerClient, JWTAuthorizationServerClient


@pytest.fixture(name="authorization_server_client")
def fixture_authorization_server_client(settings):
    """Generate an Authorization Server client."""
    settings.OIDC_OP_URL = "https://auth.example.com/api/v2"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.example.com/api/v2/introspect"

    return AuthorizationServerClient()


@pytest.fixture(name="jwt_authorization_server_client")
def fixture_jwt_authorization_server_client(settings):
    """Generate an Authorization Server client using JWT."""
    settings.OIDC_OP_URL = "https://auth.example.com/api/v2"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.example.com/api/v2/introspect"
    settings.OIDC_OP_JWKS_ENDPOINT = "https://auth.example.com/api/v2/jwks"

    return JWTAuthorizationServerClient()


def test_authorization_server_client_initialization(settings):
    """Test the AuthorizationServerClient initialization."""
    settings.OIDC_OP_URL = "https://auth.example.com/api/v2"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.example.com/api/v2/introspect"

    new_client = AuthorizationServerClient()

    assert new_client.url == "https://auth.example.com/api/v2"
    assert new_client._url_introspection == "https://auth.example.com/api/v2/introspect"
    assert new_client._verify_ssl is True
    assert new_client._timeout == 5
    assert new_client._proxy is None


def test_jwt_authorization_server_client_initialization(settings):
    """Test the JWTAuthorizationServerClient initialization."""
    settings.OIDC_OP_URL = "https://auth.example.com/api/v2"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.example.com/api/v2/introspect"
    settings.OIDC_OP_JWKS_ENDPOINT = "https://auth.example.com/api/v2/jwks"

    new_client = JWTAuthorizationServerClient()

    assert new_client.url == "https://auth.example.com/api/v2"
    assert new_client._url_introspection == "https://auth.example.com/api/v2/introspect"
    assert new_client._url_jwks == "https://auth.example.com/api/v2/jwks"
    assert new_client._verify_ssl is True
    assert new_client._timeout == 5
    assert new_client._proxy is None


def test_introspection_headers(authorization_server_client):
    """Test the introspection headers to ensure they match the expected values."""
    assert authorization_server_client._introspection_headers == {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }


def test_jwt_introspection_headers(jwt_authorization_server_client):
    """Test the introspection headers to ensure they match the expected values."""
    assert jwt_authorization_server_client._introspection_headers == {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/token-introspection+jwt",
    }


@patch("requests.post")
def test_get_introspection_success(mock_post, authorization_server_client):
    """Test 'get_introspection' method with a successful response."""
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.text = "introspection response"
    mock_post.return_value = mock_response

    result = authorization_server_client.get_introspection("client_id", "client_secret", "token")
    assert result == "introspection response"

    mock_post.assert_called_once_with(
        "https://auth.example.com/api/v2/introspect",
        data={
            "client_id": "client_id",
            "client_secret": "client_secret",
            "token": "token",
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        verify=True,
        timeout=5,
        proxies=None,
    )


@patch("requests.post", side_effect=HTTPError())
# pylint: disable=(unused-argument
def test_get_introspection_error(mock_post, authorization_server_client):
    """Test 'get_introspection' method with an HTTPError."""
    with pytest.raises(HTTPError):
        authorization_server_client.get_introspection("client_id", "client_secret", "token")


@patch("requests.get")
def test_get_jwks_success(mock_get, jwt_authorization_server_client):
    """Test 'get_jwks' method with a successful response."""
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"jwks": "foo"}
    mock_get.return_value = mock_response

    result = jwt_authorization_server_client.get_jwks()
    assert result == {"jwks": "foo"}

    mock_get.assert_called_once_with(
        "https://auth.example.com/api/v2/jwks",
        verify=jwt_authorization_server_client._verify_ssl,
        timeout=jwt_authorization_server_client._timeout,
        proxies=jwt_authorization_server_client._proxy,
    )


@patch("requests.get")
def test_get_jwks_error(mock_get, jwt_authorization_server_client):
    """Test 'get_jwks' method with an HTTPError."""
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = HTTPError(response=MagicMock(status=500))
    mock_get.return_value = mock_response

    with pytest.raises(HTTPError):
        jwt_authorization_server_client.get_jwks()


@patch("requests.get")
def test_import_public_keys_valid(mock_get, jwt_authorization_server_client):
    """Test 'import_public_keys' method with a successful response."""
    mocked_key = RSAKey.generate_key(2048)

    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"keys": [mocked_key.as_dict()]}
    mock_get.return_value = mock_response

    response = jwt_authorization_server_client.import_public_keys()

    assert isinstance(response, KeySet)
    assert response.as_dict() == KeySet([mocked_key]).as_dict()


@patch("requests.get")
def test_import_public_keys_http_error(mock_get, jwt_authorization_server_client):
    """Test 'import_public_keys' method with an HTTPError."""
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = HTTPError(response=MagicMock(status=500))
    mock_get.return_value = mock_response

    with pytest.raises(HTTPError):
        jwt_authorization_server_client.import_public_keys()


@patch("requests.get")
def test_import_public_keys_empty_jwks(mock_get, jwt_authorization_server_client):
    """Test 'import_public_keys' method with empty keys response."""
    jwks1 = KeySet.generate_key_set("RSA", 2048)
    jwks1_dict = jwks1.as_dict()

    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = jwks1_dict
    mock_get.return_value = mock_response

    response = jwt_authorization_server_client.import_public_keys()

    assert isinstance(response, KeySet)
    assert response.as_dict() == {
        "keys": jwks1_dict["keys"],
    }


@patch("requests.get")
def test_import_public_keys_invalid_jwks(mock_get, jwt_authorization_server_client):
    """Test 'import_public_keys' method with invalid keys response."""
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"keys": [{"foo": "foo"}]}
    mock_get.return_value = mock_response

    with pytest.raises(MissingKeyTypeError, match="Missing key type"):
        jwt_authorization_server_client.import_public_keys()
