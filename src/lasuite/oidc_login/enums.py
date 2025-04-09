"""Enum for OIDC login."""

from enum import StrEnum


# OIDC_OP_USER_ENDPOINT allowed values
class OIDCUserEndpointFormat(StrEnum):
    """Enum for OIDC OP User Endpoint."""

    JWT = "jwt"
    JSON = "json"
    AUTO = "auto"
