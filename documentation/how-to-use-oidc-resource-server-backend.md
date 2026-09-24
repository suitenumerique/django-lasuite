# Using the OIDC Resource Server Backend

This guide explains how to integrate and configure the `ResourceServerBackend` in your Django project for secure API access using OpenID Connect (OIDC) token introspection.

## Overview

The `ResourceServerBackend` allows your application to act as an OAuth 2.0 resource server, validating access tokens through introspection with an authorization server. This enables secure API access control using OIDC standards.

## Installation

1. Ensure you have the necessary packages installed:

```bash
pip install "django-lasuite[oidc-resource-server]"
```

## Configuration

### Settings

Add the following to your Django settings:

```python
# Resource Server Backend
OIDC_RS_BACKEND_CLASS = "lasuite.oidc_resource_server.backend.ResourceServerBackend"

# Resource Server Configuration
OIDC_RS_AUDIENCE_CLAIM = "client_id"  # The claim used to identify the audience
OIDC_RS_ENCRYPTION_ENCODING = "A256GCM"  # Encryption encoding algorithm
OIDC_RS_ENCRYPTION_ALGO = "RSA-OAEP"  # Encryption algorithm
OIDC_RS_SIGNING_ALGO = "ES256"  # Signing algorithm
OIDC_RS_SCOPES = ["groups"]  # Required scopes for authentication

# Private key for encryption/decryption
OIDC_RS_PRIVATE_KEY_STR = """-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----"""
OIDC_RS_ENCRYPTION_KEY_TYPE = "RSA"  # Key type (RSA, EC, etc.)

# Client credentials
OIDC_RS_CLIENT_ID = "your-client-id"
OIDC_RS_CLIENT_SECRET = "your-client-secret"

# Authorization server endpoints
OIDC_OP_URL = "https://your-provider.com/"
OIDC_OP_TOKEN_ENDPOINT = "https://your-provider.com/token"
OIDC_OP_USER_ENDPOINT = "https://your-provider.com/userinfo"
OIDC_OP_INTROSPECTION_ENDPOINT = "https://your-provider.com/token/introspect"
OIDC_OP_USER_ENDPOINT_FORMAT = "AUTO"  # AUTO, JSON, or JWT
```

The `OIDC_RS_CLIENT_ID` and `OIDC_RS_CLIENT_SECRET` settings identify the resource
server's client for token introspection. They are distinct from the `OIDC_RP_*`
settings used for OIDC login.

### URLs Configuration

Include the OIDC Resource Server URLs in your project's `urls.py`:

```python
from django.urls import include, path

urlpatterns = [
    # Your other URLs
    path("", include("lasuite.oidc_resource_server.urls")),
]
```

This will expose the JWKS endpoint (`/jwks`) which provides the public key used for token verification.

## Usage in Views

To secure your API views, use the authorization backend with Django REST Framework:

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from lasuite.oidc_resource_server.authentication import ResourceServerAuthentication


class SecureAPIView(APIView):
    authentication_classes = [ResourceServerAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Your secure view logic here
        return Response({"message": "Authenticated access"})
```

## Token Verification Flow

1. Client sends request with access token in Authorization header
2. `ResourceServerBackend` intercepts the request
3. Backend sends token to authorization server for introspection
4. Backend validates returned claims (issuer, audience, etc.)
5. Backend checks that the user matching the token's `sub` is active
6. If valid, request is processed; otherwise, authentication fails

### Inactive users

The `active` claim of the introspection response is about the token, not about the
user: a token of an inactive local user (deactivated from the admin or merged into
another account, for instance) is refused with a `401` response, just like DRF's
session authentication would.

## Creating users on the fly

By default, a token whose `sub` does not match any existing user is rejected with a 401:
users must have logged in to the application once before calling it through the resource server.

Set `OIDC_RS_CREATE_USER` to create them on the fly instead:

```python
OIDC_RS_CREATE_USER = True  # Default: False
OIDC_CREATE_USER = True  # Must be True with the default backend

# Optional: the backend used to get or create the unknown user.
OIDC_RS_USER_CREATION_BACKEND_CLASS = "lasuite.oidc_login.backends.OIDCAuthenticationBackend"
```

The unknown user is then fetched from the userinfo endpoint with the same access token, so the
token must carry the scopes needed for the expected claims (e.g. `email`). It is created with the
same rules as a regular login.
If the userinfo `sub` does not match the introspected one, authentication fails.

## Advanced: JWT Resource Server

For JWT-based introspection (RFC 9701), use the `JWTResourceServerBackend`:

```python
OIDC_RS_BACKEND_CLASS = "lasuite.oidc_resource_server.backend.JWTResourceServerBackend"
```

This implementation handles JWT format introspection responses that are signed and encrypted, providing an additional layer of security.

## Key Management

The resource server requires a key pair:
- The private key is used for decryption and stored securely in your settings
- The public key is exposed via the JWKS endpoint for the authorization server

Generate a suitable RSA key, like using OpenSSL:

```bash
openssl genrsa -out private_key.pem 2048
```
