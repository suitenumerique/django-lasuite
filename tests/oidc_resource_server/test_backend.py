"""Test for the Resource Server (RS) Backend."""

import json

# pylint: disable=W0212
from logging import Logger
from unittest.mock import ANY, Mock, patch

import pytest
import responses
from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from joserfc.errors import InvalidClaimError, InvalidTokenError
from joserfc.jwt import JWTClaimsRegistry, Token

from lasuite.oidc_resource_server.backend import JWTResourceServerBackend, ResourceServerBackend
from lasuite.oidc_resource_server.clients import AuthorizationServerClient


@pytest.fixture(name="mock_token")
def fixture_mock_token():
    """Mock a token."""
    mock_token = Mock()
    mock_token.claims = {"sub": "user123", "iss": "https://auth.server.com"}
    return mock_token


@pytest.fixture(name="resource_server_backend")
def fixture_resource_server_backend(settings):
    """Generate a Resource Server backend."""
    settings.OIDC_RS_CLIENT_ID = "client_id"
    settings.OIDC_RS_CLIENT_SECRET = "client_secret"
    settings.OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"
    settings.OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"
    settings.OIDC_RS_SIGNING_ALGO = "ES256"
    settings.OIDC_RS_SCOPES = ["groups"]

    settings.OIDC_OP_URL = "https://auth.server.com"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.server.com/introspect"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 10
    settings.OIDC_PROXY = None
    return ResourceServerBackend()


@pytest.fixture(name="jwt_resource_server_backend")
def fixture_jwt_resource_server_backend(settings):
    """Generate a Resource Server backend."""
    settings.OIDC_RS_CLIENT_ID = "client_id"
    settings.OIDC_RS_CLIENT_SECRET = "client_secret"
    settings.OIDC_RS_SCOPES = ["groups"]

    settings.OIDC_OP_URL = "https://auth.server.com"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.server.com/introspect"
    settings.OIDC_OP_JWKS_ENDPOINT = "https://auth.server.com/jwks"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 10
    settings.OIDC_PROXY = None
    return JWTResourceServerBackend()


@patch.object(auth, "get_user_model", return_value="foo")
def test_backend_initialization(mock_get_user_model, settings):
    """Test the ResourceServerBackend initialization."""
    settings.OIDC_RS_CLIENT_ID = "client_id"
    settings.OIDC_RS_CLIENT_SECRET = "client_secret"
    settings.OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"
    settings.OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"
    settings.OIDC_RS_SIGNING_ALGO = "RS256"
    settings.OIDC_RS_SCOPES = ["scopes"]

    settings.OIDC_OP_URL = "https://auth.server.com"
    settings.OIDC_OP_INTROSPECTION_ENDPOINT = "https://auth.server.com/introspect"
    settings.OIDC_VERIFY_SSL = True
    settings.OIDC_TIMEOUT = 10
    settings.OIDC_PROXY = None
    backend = ResourceServerBackend()

    mock_get_user_model.assert_called_once()
    assert backend.UserModel == "foo"

    assert backend._client_id == "client_id"
    assert backend._client_secret == "client_secret"
    assert backend._encryption_encoding == "A256GCM"
    assert backend._encryption_algorithm == "RSA-OAEP"
    assert backend._signing_algorithm == "RS256"
    assert backend._scopes == ["scopes"]

    assert isinstance(backend._authorization_server_client, AuthorizationServerClient)
    assert isinstance(backend._introspection_claims_registry, JWTClaimsRegistry)

    assert backend._introspection_claims_registry.options == {
        "active": {"essential": True},
        "client_id": {"essential": False},
        "iss": {"essential": True, "value": "https://auth.server.com"},
        "scope": {"essential": False},
    }


@patch.object(ResourceServerBackend, "get_user", return_value="user")
def test_get_or_create_user(mock_get_user, resource_server_backend):
    """Test 'get_or_create_user' method."""
    access_token = "access_token"
    res = resource_server_backend.get_or_create_user(access_token, None, None)

    mock_get_user.assert_called_once_with(access_token)
    assert res == "user"


def test_verify_claims_success(resource_server_backend, mock_token):
    """Test '_verify_claims' method with a successful response."""
    with patch.object(resource_server_backend._introspection_claims_registry, "validate") as mock_validate:
        resource_server_backend._verify_claims(mock_token)
        mock_validate.assert_called_once_with(mock_token.claims)


def test_verify_claims_invalid_claim_error(resource_server_backend, mock_token):
    """Test '_verify_claims' method with an invalid claim error."""
    with patch.object(resource_server_backend._introspection_claims_registry, "validate") as mock_validate:
        mock_validate.side_effect = InvalidClaimError("claim_name")

        expected_message = "Failed to validate token's claims"
        with patch.object(Logger, "debug") as mock_logger_debug:
            with pytest.raises(SuspiciousOperation, match=expected_message):
                resource_server_backend._verify_claims(mock_token)
            mock_logger_debug.assert_called_once_with("%s. Exception:", expected_message, exc_info=True)


def test_verify_claims_invalid_token_error(resource_server_backend, mock_token):
    """Test '_verify_claims' method with an invalid token error."""
    with patch.object(resource_server_backend._introspection_claims_registry, "validate") as mock_validate:
        mock_validate.side_effect = InvalidTokenError

        expected_message = "Failed to validate token's claims"
        with patch.object(Logger, "debug") as mock_logger_debug:
            with pytest.raises(SuspiciousOperation, match=expected_message):
                resource_server_backend._verify_claims(mock_token)
            mock_logger_debug.assert_called_once_with("%s. Exception:", expected_message, exc_info=True)


def test_decode_success(resource_server_backend):
    """Test '_decode' method with a successful response."""
    encoded_token = "valid_encoded_token"
    public_key_set = Mock()

    expected_decoded_token = {"sub": "user123"}

    with patch("joserfc.jwt.decode", return_value=expected_decoded_token) as mock_decode:
        decoded_token = resource_server_backend._decode(encoded_token, public_key_set)

        mock_decode.assert_called_once_with("valid_encoded_token", public_key_set, algorithms=["ES256"])

        assert decoded_token == expected_decoded_token


def test_decode_failure(resource_server_backend):
    """Test '_decode' method with a ValueError."""
    encoded_token = "invalid_encoded_token"
    public_key_set = Mock()

    with patch("joserfc.jwt.decode", side_effect=ValueError), patch.object(Logger, "debug") as mock_logger_debug:
        with pytest.raises(SuspiciousOperation, match="Token decoding failed"):
            resource_server_backend._decode(encoded_token, public_key_set)

        mock_logger_debug.assert_called_once_with("%s. Exception:", "Token decoding failed", exc_info=True)


def test_decrypt_success(resource_server_backend):
    """Test '_decrypt' method with a successful response."""
    encrypted_token = "valid_encrypted_token"
    private_key = "private_key"

    expected_decrypted_token = Mock()
    expected_decrypted_token.plaintext = "blah"

    with patch("joserfc.jwe.decrypt_compact", return_value=expected_decrypted_token) as mock_decrypt:
        decrypted_token = resource_server_backend._decrypt(encrypted_token, private_key)
        mock_decrypt.assert_called_once_with(encrypted_token, private_key, registry=ANY)

        registry = mock_decrypt.call_args[1]["registry"]
        assert registry.allowed == ["RSA-OAEP", "A256GCM"]
        assert decrypted_token == "blah"


def test_decrypt_with_extra_headers(resource_server_backend):
    """Test '_decrypt' method with a JWE containing extra headers 'iss' and 'aud'."""
    encrypted_token = "valid_encrypted_token_with_extra_headers"
    private_key = "private_key"

    # Créer un mock JWE avec des en-têtes supplémentaires
    mock_jwe = Mock()
    mock_jwe.plaintext = "decrypted_content"
    mock_jwe.header = {"alg": "RSA-OAEP", "enc": "A256GCM", "iss": "https://auth.server.com", "aud": "client_id"}

    with patch("joserfc.jwe.decrypt_compact", return_value=mock_jwe) as mock_decrypt:
        # Appel de la méthode à tester
        decrypted_token = resource_server_backend._decrypt(encrypted_token, private_key)

        # Vérifier que le registry contient bien les définitions pour iss et aud
        registry = mock_decrypt.call_args[1]["registry"]
        assert "iss" in registry.header_registry
        assert "aud" in registry.header_registry

        assert registry.allowed == ["RSA-OAEP", "A256GCM"]

        # Vérifier que le contenu déchiffré est correct
        assert decrypted_token == "decrypted_content"


def test_decrypt_failure(resource_server_backend):
    """Test '_decrypt' method with an Exception."""
    encrypted_token = "invalid_encrypted_token"
    private_key = "private_key"

    with patch("joserfc.jwe.decrypt_compact", side_effect=Exception("Decryption error")):
        expected_message = "Token decryption failed"
        with patch.object(Logger, "debug") as mock_logger_debug:
            with pytest.raises(SuspiciousOperation, match=expected_message):
                resource_server_backend._decrypt(encrypted_token, private_key)
            mock_logger_debug.assert_called_once_with("%s. Exception:", expected_message, exc_info=True)


def test_resource_server_backend_introspect_success(resource_server_backend):
    """Test '_introspect' method with a successful response."""
    token = "valid_token"
    json_data = {"sub": "user123"}

    resource_server_backend._authorization_server_client.get_introspection = Mock(return_value=json.dumps(json_data))

    result = resource_server_backend._introspect(token)

    assert result.claims == json_data
    resource_server_backend._authorization_server_client.get_introspection.assert_called_once_with(
        "client_id", "client_secret", token
    )


@patch(
    "lasuite.oidc_resource_server.utils.import_private_key_from_settings",
    return_value="private_key",
)
# pylint: disable=unused-argument
def test_jwt_resource_server_backend_introspect_success(
    mock_import_private_key_from_settings, jwt_resource_server_backend
):
    """Test '_introspect' method with a successful response."""
    jwt_rs_backend = jwt_resource_server_backend  # prevent line too long

    token = "valid_token"
    jwe = "valid_jwe"
    jws = "valid_jws"
    jwt = {
        "aud": "client_id",
        "iss": "https://auth.server.com",
        "token_introspection": {
            "sub": "user123",
            "aud": "client_id",
        },
    }

    jwt_rs_backend._authorization_server_client.get_introspection = Mock(return_value=jwe)
    jwt_rs_backend._decrypt = Mock(return_value=jws)
    jwt_rs_backend._authorization_server_client.import_public_keys = Mock(return_value="public_key_set")
    jwt_rs_backend._decode = Mock(return_value=Token({}, jwt))

    result = jwt_rs_backend._introspect(token)

    assert result.claims == {
        "sub": "user123",
        "aud": "client_id",
    }

    jwt_rs_backend._authorization_server_client.get_introspection.assert_called_once_with(
        "client_id", "client_secret", token
    )
    jwt_rs_backend._decrypt.assert_called_once_with(jwe, private_key="private_key")
    jwt_rs_backend._authorization_server_client.import_public_keys.assert_called_once()
    jwt_rs_backend._decode.assert_called_once_with(jws, "public_key_set")


@responses.activate
def test_introspect_introspection_failure(resource_server_backend):
    """Test '_introspect' method when introspection to the AS fails."""
    responses.post("https://auth.server.com/introspect", status=500)

    with patch.object(Logger, "debug") as mock_logger_debug:
        expected_message = "Could not fetch introspection"
        with pytest.raises(SuspiciousOperation, match=expected_message):
            resource_server_backend._introspect("invalid_token")

        mock_logger_debug.assert_called_once_with("%s. Exception:", expected_message, exc_info=True)


@patch(
    "lasuite.oidc_resource_server.utils.import_private_key_from_settings",
    return_value="private_key",
)
@responses.activate
# pylint: disable=unused-argument
def test_jwt_resource_server_backend_introspect_public_key_import_failure(
    mock_import_private_key_from_settings, jwt_resource_server_backend
):
    """Test '_introspect' method when fetching AS's jwks fails."""
    token = "valid_token"
    jwe = "valid_jwe"
    jws = "valid_jws"

    jwt_resource_server_backend._authorization_server_client.get_introspection = Mock(return_value=jwe)
    jwt_resource_server_backend._decrypt = Mock(return_value=jws)

    responses.get("https://auth.server.com/jwks", status=500)

    with patch.object(Logger, "debug") as mock_logger_debug:
        expected_message = "Could not get authorization server JWKS"
        with pytest.raises(SuspiciousOperation, match=expected_message):
            jwt_resource_server_backend._introspect(token)

        mock_logger_debug.assert_called_once_with("%s. Exception:", expected_message, exc_info=True)


def test_verify_user_info_success(resource_server_backend, settings):
    """Test '_verify_user_info' with a successful response."""
    # test default OIDC_RS_AUDIENCE_CLAIM = client_id
    introspection_response = {"active": True, "scope": "groups", "client_id": "123"}
    result = resource_server_backend._verify_user_info(introspection_response)
    assert result == introspection_response

    # test OIDC_RS_AUDIENCE_CLAIM = aud is taken into account
    settings.OIDC_RS_AUDIENCE_CLAIM = "aud"
    introspection_response = {"active": True, "scope": "groups", "aud": "123"}
    result = resource_server_backend._verify_user_info(introspection_response)
    assert result == introspection_response


def test_verify_user_info_inactive(resource_server_backend):
    """Test '_verify_user_info' with an inactive introspection response."""
    introspection_response = {"active": False, "scope": "groups"}

    with patch.object(Logger, "info") as mock_logger_info:
        with pytest.raises(SuspiciousOperation, match="Introspected user is not active"):
            resource_server_backend._verify_user_info(introspection_response)

        mock_logger_info.assert_called_once_with("Token introspection refused because user is not active")


def test_verify_user_info_missing_scope_claim(resource_server_backend):
    """Test '_verify_user_info' with wrong requested scopes."""
    introspection_response = {"active": True}

    with patch.object(Logger, "warning") as mock_logger_warning:
        with pytest.raises(SuspiciousOperation, match="Token introspection failed due to missing 'scope' claim."):
            resource_server_backend._verify_user_info(introspection_response)

        mock_logger_warning.assert_called_once_with("Token introspection failed due to missing 'scope' claim.")


def test_verify_user_info_wrong_scopes(resource_server_backend):
    """Test '_verify_user_info' with wrong requested scopes."""
    introspection_response = {"active": True, "scope": "wrong-scopes"}

    with patch.object(Logger, "warning") as mock_logger_warning:
        with pytest.raises(SuspiciousOperation, match="Introspection response is missing required scopes."):
            resource_server_backend._verify_user_info(introspection_response)

        mock_logger_warning.assert_called_once_with(
            "Token introspection failed, missing required scopes: %s", ["wrong-scopes"]
        )


def test_verify_user_info_missing_audience(resource_server_backend):
    """Test '_verify_user_info' with wrong requested scopes."""
    introspection_response = {"active": True, "scope": "groups"}

    with patch.object(Logger, "warning") as mock_logger_warning:
        with pytest.raises(SuspiciousOperation, match="Introspection response does not provide source audience."):
            resource_server_backend._verify_user_info(introspection_response)

        mock_logger_warning.assert_called_once_with("Token introspection failed, missing %s claim", "client_id")


def test_resource_server_backend_get_user_success(resource_server_backend):
    """Test '_get_user' with a successful response."""
    access_token = "valid_access_token"
    mock_jwt = Mock()
    mock_claims = {"sub": "user123", "client_id": "123"}
    mock_user = Mock()

    resource_server_backend._introspect = Mock(return_value=mock_jwt)
    resource_server_backend._verify_claims = Mock(return_value=mock_claims)
    resource_server_backend._verify_user_info = Mock(return_value=mock_claims)
    resource_server_backend.UserModel.objects.get = Mock(return_value=mock_user)

    user = resource_server_backend.get_user(access_token)

    assert user == mock_user
    resource_server_backend._introspect.assert_called_once_with(access_token)
    resource_server_backend._verify_claims.assert_called_once_with(mock_jwt)
    resource_server_backend._verify_user_info.assert_called_once_with(mock_claims)
    resource_server_backend.UserModel.objects.get.assert_called_once_with(sub="user123")


def test_get_user_could_not_introspect(resource_server_backend):
    """Test '_get_user' with introspection failing."""
    access_token = "valid_access_token"

    resource_server_backend._introspect = Mock(side_effect=SuspiciousOperation("Invalid jwt"))
    resource_server_backend._verify_claims = Mock()
    resource_server_backend._verify_user_info = Mock()

    with pytest.raises(SuspiciousOperation, match="Invalid jwt"):
        resource_server_backend.get_user(access_token)

    resource_server_backend._introspect.assert_called_once_with(access_token)
    resource_server_backend._verify_claims.assert_not_called()
    resource_server_backend._verify_user_info.assert_not_called()


def test_get_user_invalid_introspection_response(resource_server_backend):
    """Test '_get_user' with an invalid introspection response."""
    access_token = "valid_access_token"
    mock_jwt = Mock()

    resource_server_backend._introspect = Mock(return_value=mock_jwt)
    resource_server_backend._verify_claims = Mock(side_effect=SuspiciousOperation("Invalid claims"))
    resource_server_backend._verify_user_info = Mock()

    with pytest.raises(SuspiciousOperation, match="Invalid claims"):
        resource_server_backend.get_user(access_token)

    resource_server_backend._introspect.assert_called_once_with(access_token)
    resource_server_backend._verify_claims.assert_called_once_with(mock_jwt)
    resource_server_backend._verify_user_info.assert_not_called()


def test_resource_server_backend_get_user_user_not_found(resource_server_backend):
    """Test '_get_user' if the user is not found."""
    access_token = "valid_access_token"
    mock_jwt = Mock()
    mock_claims = {"sub": "user123"}

    resource_server_backend._introspect = Mock(return_value=mock_jwt)
    resource_server_backend._verify_claims = Mock(return_value=mock_claims)
    resource_server_backend._verify_user_info = Mock(return_value=mock_claims)
    resource_server_backend.UserModel.objects.get = Mock(side_effect=resource_server_backend.UserModel.DoesNotExist)

    with patch.object(Logger, "debug") as mock_logger_debug:
        user = resource_server_backend.get_user(access_token)
        assert user is None
        resource_server_backend._introspect.assert_called_once_with(access_token)
        resource_server_backend._verify_claims.assert_called_once_with(mock_jwt)
        resource_server_backend._verify_user_info.assert_called_once_with(mock_claims)
        resource_server_backend.UserModel.objects.get.assert_called_once_with(sub="user123")

        mock_logger_debug.assert_called_once_with("Login failed: No user with %s found", "user123")


def test_get_user_no_user_identification(resource_server_backend):
    """Test '_get_user' if the response miss a user identification."""
    access_token = "valid_access_token"
    mock_jwt = Mock()
    mock_claims = {"token_introspection": {}}

    resource_server_backend._introspect = Mock(return_value=mock_jwt)
    resource_server_backend._verify_claims = Mock(return_value=mock_claims)
    resource_server_backend._verify_user_info = Mock(return_value=mock_claims["token_introspection"])

    expected_message = "User info contained no recognizable user identification"
    with patch.object(Logger, "debug") as mock_logger_debug:
        with pytest.raises(SuspiciousOperation, match=expected_message):
            resource_server_backend.get_user(access_token)

        mock_logger_debug.assert_called_once_with(expected_message)


@responses.activate
def test_full_authentication_with_inactive_user(caplog, resource_server_backend):
    """
    Test the full authentication process when the user is inactive.

    In such case the introspection response will only contain the active claim.
    """
    responses.post(
        "https://auth.server.com/introspect",
        status=200,
        body=json.dumps({"iss": "https://auth.server.com", "active": False}),
    )

    with pytest.raises(SuspiciousOperation, match="Introspected user is not active"):
        resource_server_backend.get_or_create_user("access_token", None, None)

    assert "Token introspection refused because user is not active" in caplog.text


@responses.activate
@patch(
    "lasuite.oidc_resource_server.utils.import_private_key_from_settings",
    return_value="private_key",
)
def test_full_jwt_authentication_with_inactive_user(
    mock_import_private_key_from_settings, caplog, jwt_resource_server_backend
):
    """
    Test the full authentication process when the user is inactive.

    In such case the introspection response will only contain the active claim.
    """
    jwt_resource_server_backend._authorization_server_client.get_introspection = Mock(return_value="valid_jwe")
    jwt_resource_server_backend._decrypt = Mock(return_value="valid_jws")
    jwt_resource_server_backend._authorization_server_client.import_public_keys = Mock(return_value="public_key_set")
    jwt_resource_server_backend._decode = Mock(
        return_value=Token(
            {},
            {
                "aud": "client_id",
                "iss": "https://auth.server.com",
                "token_introspection": {"active": False},
            },
        )
    )

    with pytest.raises(SuspiciousOperation, match="Introspected user is not active"):
        jwt_resource_server_backend.get_or_create_user("access_token", None, None)

    assert "Token introspection refused because user is not active" in caplog.text
