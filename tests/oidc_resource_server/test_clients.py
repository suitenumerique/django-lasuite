"""Test for the Resource Server (RS) clients classes."""

# pylint: disable=W0212

import pytest
import responses
from joserfc.errors import MissingKeyTypeError
from joserfc.jwk import KeySet, RSAKey
from requests.exceptions import HTTPError
from responses import matchers

from lasuite.oidc_resource_server.clients import AuthorizationServerClient, JWTAuthorizationServerClient

INTROSPECTION_URL = "https://auth.example.com/api/v2/introspect"
JWKS_URL = "https://auth.example.com/api/v2/jwks"
# Explicit values: ``requests`` merges defaults with the environment
# (``REQUESTS_CA_BUNDLE``, ``HTTPS_PROXY``), which would make assertions flaky.
TEST_PROXY = {"https": "http://proxy.example.com:3128"}


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


@responses.activate
def test_get_introspection_success(authorization_server_client):
    """Test 'get_introspection' method with a successful response."""
    authorization_server_client._verify_ssl = False
    authorization_server_client._proxy = TEST_PROXY
    responses.post(
        INTROSPECTION_URL,
        body="introspection response",
        match=[
            matchers.urlencoded_params_matcher(
                {
                    "client_id": "client_id",
                    "client_secret": "client_secret",
                    "token": "token",
                }
            ),
            matchers.header_matcher(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                }
            ),
        ],
    )

    result = authorization_server_client.get_introspection("client_id", "client_secret", "token")
    assert result == "introspection response"

    assert len(responses.calls) == 1
    request_kwargs = responses.calls[0].request.req_kwargs
    assert request_kwargs["verify"] is False
    assert request_kwargs["timeout"] == 5
    assert request_kwargs["proxies"]["https"] == TEST_PROXY["https"]


@responses.activate
def test_get_introspection_error(authorization_server_client):
    """Test 'get_introspection' method with an HTTPError."""
    responses.post(INTROSPECTION_URL, status=500)

    with pytest.raises(HTTPError):
        authorization_server_client.get_introspection("client_id", "client_secret", "token")


@responses.activate
def test_get_jwks_success(jwt_authorization_server_client):
    """Test 'get_jwks' method with a successful response."""
    jwt_authorization_server_client._verify_ssl = False
    jwt_authorization_server_client._proxy = TEST_PROXY
    responses.get(JWKS_URL, json={"jwks": "foo"})

    result = jwt_authorization_server_client.get_jwks()
    assert result == {"jwks": "foo"}

    assert len(responses.calls) == 1
    request_kwargs = responses.calls[0].request.req_kwargs
    assert request_kwargs["verify"] is False
    assert request_kwargs["timeout"] == 5
    assert request_kwargs["proxies"]["https"] == TEST_PROXY["https"]


@responses.activate
def test_get_jwks_error(jwt_authorization_server_client):
    """Test 'get_jwks' method with an HTTPError."""
    responses.get(JWKS_URL, status=500)

    with pytest.raises(HTTPError):
        jwt_authorization_server_client.get_jwks()


@responses.activate
def test_import_public_keys_valid(jwt_authorization_server_client):
    """Test 'import_public_keys' method with a successful response."""
    mocked_key = RSAKey.generate_key(2048)
    responses.get(JWKS_URL, json={"keys": [mocked_key.as_dict()]})

    response = jwt_authorization_server_client.import_public_keys()

    assert isinstance(response, KeySet)
    assert response.as_dict() == KeySet([mocked_key]).as_dict()


@responses.activate
def test_import_public_keys_http_error(jwt_authorization_server_client):
    """Test 'import_public_keys' method with an HTTPError."""
    responses.get(JWKS_URL, status=500)

    with pytest.raises(HTTPError):
        jwt_authorization_server_client.import_public_keys()


@responses.activate
def test_import_public_keys_empty_jwks(jwt_authorization_server_client):
    """Test 'import_public_keys' method with empty keys response."""
    jwks1 = KeySet.generate_key_set("RSA", 2048)
    jwks1_dict = jwks1.as_dict()
    responses.get(JWKS_URL, json=jwks1_dict)

    response = jwt_authorization_server_client.import_public_keys()

    assert isinstance(response, KeySet)
    assert response.as_dict() == {
        "keys": jwks1_dict["keys"],
    }


@responses.activate
def test_import_public_keys_invalid_jwks(jwt_authorization_server_client):
    """Test 'import_public_keys' method with invalid keys response."""
    responses.get(JWKS_URL, json={"keys": [{"foo": "foo"}]})

    with pytest.raises(MissingKeyTypeError, match="Missing key type"):
        jwt_authorization_server_client.import_public_keys()
