"""Tests for the authentication process of the resource server."""

import base64
import json

import pytest
import responses
from joserfc import jwe as jose_jwe
from joserfc import jwt as jose_jwt
from joserfc.jwk import RSAKey
from rest_framework.request import Request as DRFRequest
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

from lasuite.oidc_resource_server.authentication import ResourceServerAuthentication, get_resource_server_backend
from tests.factories import UserFactory

pytestmark = pytest.mark.django_db


@pytest.fixture(name="jwt_resource_server_backend")
def jwt_resource_server_backend_fixture(settings):
    """Fixture to switch the backend to the JWTResourceServerBackend."""
    _original_backend = str(settings.OIDC_RS_BACKEND_CLASS)

    settings.OIDC_RS_BACKEND_CLASS = "lasuite.oidc_resource_server.backend.JWTResourceServerBackend"
    get_resource_server_backend.cache_clear()

    yield

    settings.OIDC_RS_BACKEND_CLASS = _original_backend
    get_resource_server_backend.cache_clear()


def build_authorization_bearer(token):
    """
    Build an Authorization Bearer header value from a token.

    This can be used like this:
    client.post(
        ...
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )
    """
    return base64.b64encode(token.encode("utf-8")).decode("utf-8")


@responses.activate
def test_resource_server_authentication_class(client, settings):
    """
    Defines the settings for the resource server
    for a full authentication with introspection process.

    This is an integration test that checks the authentication process
    when using the ResourceServerAuthentication class.

    This test asserts the DRF request object contains the
    `resource_server_token_audience` attribute which is used in
    the resource server views.
    """
    assert settings.OIDC_RS_BACKEND_CLASS == "lasuite.oidc_resource_server.backend.ResourceServerBackend"

    settings.OIDC_RS_CLIENT_ID = "some_client_id"
    settings.OIDC_RS_CLIENT_SECRET = "some_client_secret"

    settings.OIDC_OP_URL = "https://oidc.example.com"
    settings.OIDC_VERIFY_SSL = False
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_JWKS_ENDPOINT = "https://oidc.example.com/jwks"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://oidc.example.com/introspect"

    responses.add(
        responses.POST,
        "https://oidc.example.com/introspect",
        json={
            "iss": "https://oidc.example.com",
            "aud": "some_client_id",  # settings.OIDC_RS_CLIENT_ID
            "sub": "very-specific-sub",
            "client_id": "some_service_provider",
            "scope": "openid groups",
            "active": True,
        },
    )

    # Try to authenticate while the user does not exist => 401
    response = client.get(
        "/users/",  # use an exising URL here
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )
    assert response.status_code == HTTP_401_UNAUTHORIZED

    # Create a user with the specific sub, the access is authorized
    UserFactory(sub="very-specific-sub")

    response = client.get(
        "/users/",  # use an exising URL here
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )

    assert response.status_code == HTTP_200_OK

    response_request = response.renderer_context.get("request")
    assert isinstance(response_request, DRFRequest)
    assert isinstance(response_request.successful_authenticator, ResourceServerAuthentication)

    # Check that the user is authenticated
    assert response_request.user.is_authenticated

    # Check the user is the expected one
    assert response_request.user.sub == "very-specific-sub"

    # Check we have the correct user info
    assert response_request.auth == {
        "active": True,
        "aud": "some_client_id",
        "client_id": "some_service_provider",
        "iss": "https://oidc.example.com",
        "scope": "openid groups",
        "sub": "very-specific-sub",
    }

    # Check the request contains the resource server token audience
    assert response_request.resource_server_token_audience == "some_service_provider"


@responses.activate
def test_jwt_resource_server_authentication_class(  # pylint: disable=unused-argument
    client, jwt_resource_server_backend, settings
):
    """
    Defines the settings for the resource server
    for a full authentication with introspection process.

    This is an integration test that checks the authentication process
    when using the ResourceServerAuthentication class.

    This test asserts the DRF request object contains the
    `resource_server_token_audience` attribute which is used in
    the resource server views.
    """
    private_key = RSAKey.generate_key(private=True)
    public_key = RSAKey.import_key(private_key.as_dict(private=False))

    settings.OIDC_RS_PRIVATE_KEY_STR = private_key.as_pem(private=True).decode()
    settings.OIDC_RS_ENCRYPTION_KEY_TYPE = "RSA"
    settings.OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"
    settings.OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"
    settings.OIDC_RS_SIGNING_ALGO = "RS256"
    settings.OIDC_RS_CLIENT_ID = "some_client_id"
    settings.OIDC_RS_CLIENT_SECRET = "some_client_secret"

    settings.OIDC_OP_URL = "https://oidc.example.com"
    settings.OIDC_VERIFY_SSL = False
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_JWKS_ENDPOINT = "https://oidc.example.com/jwks"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://oidc.example.com/introspect"

    # Mock the JWKS endpoint
    public_jwk = private_key.as_dict(
        private=False,
        kty=settings.OIDC_RS_ENCRYPTION_KEY_TYPE,
        alg=settings.OIDC_RS_SIGNING_ALGO,
        use="sig",
        kid="1234567890",
    )
    responses.add(
        responses.GET,
        settings.OIDC_OP_JWKS_ENDPOINT,
        body=json.dumps({"keys": [public_jwk]}),
    )

    def encrypt_jwt(json_data):
        """Encrypt the JWT token for the backend to decrypt."""
        token = jose_jwt.encode(
            {
                "kid": "1234567890",
                "alg": settings.OIDC_RS_SIGNING_ALGO,
            },
            json_data,
            private_key,
            algorithms=[settings.OIDC_RS_SIGNING_ALGO],
        )

        return jose_jwe.encrypt_compact(
            protected={
                "alg": settings.OIDC_RS_ENCRYPTION_ALGO,
                "enc": settings.OIDC_RS_ENCRYPTION_ENCODING,
            },
            plaintext=token,
            public_key=public_key,
            algorithms=[
                settings.OIDC_RS_ENCRYPTION_ALGO,
                settings.OIDC_RS_ENCRYPTION_ENCODING,
            ],
        )

    responses.add(
        responses.POST,
        "https://oidc.example.com/introspect",
        body=encrypt_jwt(
            {
                "iss": "https://oidc.example.com",
                "aud": "some_client_id",  # settings.OIDC_RS_CLIENT_ID
                "token_introspection": {
                    "sub": "very-specific-sub",
                    "iss": "https://oidc.example.com",
                    "aud": "some_client_id",
                    "client_id": "some_service_provider",
                    "scope": "openid groups",
                    "active": True,
                },
            }
        ),
    )

    # Try to authenticate while the user does not exist => 401
    response = client.get(
        "/users/",  # use an exising URL here
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )
    assert response.status_code == HTTP_401_UNAUTHORIZED

    # Create a user with the specific sub, the access is authorized
    UserFactory(sub="very-specific-sub")

    response = client.get(
        "/users/",  # use an exising URL here
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )

    assert response.status_code == HTTP_200_OK

    response_request = response.renderer_context.get("request")
    assert isinstance(response_request, DRFRequest)
    assert isinstance(response_request.successful_authenticator, ResourceServerAuthentication)

    # Check that the user is authenticated
    assert response_request.user.is_authenticated

    # Check the user is the expected one
    assert response_request.user.sub == "very-specific-sub"

    # Check we have the correct user info
    assert response_request.auth == {
        "active": True,
        "aud": "some_client_id",
        "client_id": "some_service_provider",
        "iss": "https://oidc.example.com",
        "scope": "openid groups",
        "sub": "very-specific-sub",
    }

    # Check the request contains the resource server token audience
    assert response_request.resource_server_token_audience == "some_service_provider"


@responses.activate
def test_resource_server_authentication_class_inactive_user(client, settings):
    """
    Test authentication with ResourceServerBackend when user is inactive (active=False).

    This is an integration test that checks the authentication process fails
    when the introspection response indicates the user is not active.
    """
    assert settings.OIDC_RS_BACKEND_CLASS == "lasuite.oidc_resource_server.backend.ResourceServerBackend"

    settings.OIDC_RS_CLIENT_ID = "some_client_id"
    settings.OIDC_RS_CLIENT_SECRET = "some_client_secret"

    settings.OIDC_OP_URL = "https://oidc.example.com"
    settings.OIDC_VERIFY_SSL = False
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_JWKS_ENDPOINT = "https://oidc.example.com/jwks"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://oidc.example.com/introspect"

    # Mock introspection response with active=False
    responses.add(
        responses.POST,
        "https://oidc.example.com/introspect",
        json={
            "active": False,  # User is not active
        },
    )

    # Try to authenticate
    response = client.get(
        "/users/",
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST  # Suspicious operation


@responses.activate
def test_jwt_resource_server_authentication_class_inactive_user(  # pylint: disable=unused-argument
    client, jwt_resource_server_backend, settings
):
    """
    Test authentication with JWTResourceServerBackend when user is inactive (active=False).

    This is an integration test that checks the authentication process fails
    when the introspection response indicates the user is not active.
    """
    private_key = RSAKey.generate_key(private=True)
    public_key = RSAKey.import_key(private_key.as_dict(private=False))

    settings.OIDC_RS_PRIVATE_KEY_STR = private_key.as_pem(private=True).decode()
    settings.OIDC_RS_ENCRYPTION_KEY_TYPE = "RSA"
    settings.OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"
    settings.OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"
    settings.OIDC_RS_SIGNING_ALGO = "RS256"
    settings.OIDC_RS_CLIENT_ID = "some_client_id"
    settings.OIDC_RS_CLIENT_SECRET = "some_client_secret"

    settings.OIDC_OP_URL = "https://oidc.example.com"
    settings.OIDC_VERIFY_SSL = False
    settings.OIDC_TIMEOUT = 5
    settings.OIDC_PROXY = None
    settings.OIDC_OP_JWKS_ENDPOINT = "https://oidc.example.com/jwks"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://oidc.example.com/introspect"

    # Mock the JWKS endpoint
    public_jwk = private_key.as_dict(
        private=False,
        kty=settings.OIDC_RS_ENCRYPTION_KEY_TYPE,
        alg=settings.OIDC_RS_SIGNING_ALGO,
        use="sig",
        kid="1234567890",
    )
    responses.add(
        responses.GET,
        settings.OIDC_OP_JWKS_ENDPOINT,
        body=json.dumps({"keys": [public_jwk]}),
    )

    def encrypt_jwt(json_data):
        """Encrypt the JWT token for the backend to decrypt."""
        token = jose_jwt.encode(
            {
                "kid": "1234567890",
                "alg": settings.OIDC_RS_SIGNING_ALGO,
            },
            json_data,
            private_key,
            algorithms=[settings.OIDC_RS_SIGNING_ALGO],
        )

        return jose_jwe.encrypt_compact(
            protected={
                "alg": settings.OIDC_RS_ENCRYPTION_ALGO,
                "enc": settings.OIDC_RS_ENCRYPTION_ENCODING,
            },
            plaintext=token,
            public_key=public_key,
            algorithms=[
                settings.OIDC_RS_ENCRYPTION_ALGO,
                settings.OIDC_RS_ENCRYPTION_ENCODING,
            ],
        )

    # Mock introspection response with active=False
    responses.add(
        responses.POST,
        "https://oidc.example.com/introspect",
        body=encrypt_jwt(
            {
                "iss": "https://oidc.example.com",
                "aud": "some_client_id",
                "token_introspection": {
                    "active": False,  # User is not active
                },
            }
        ),
    )

    # Try to authenticate
    response = client.get(
        "/users/",
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {build_authorization_bearer('some_token')}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST  # Suspicious operation
