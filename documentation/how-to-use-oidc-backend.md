# Using the OIDC Authentication Backend

This guide explains how to integrate and configure the `OIDCAuthenticationBackend` in your Django project for OpenID Connect (OIDC) authentication.

## Installation

1. Ensure you have the necessary packages installed:

```bash
pip install django-lasuite
```

## Configuration

### Settings

Add the following to your Django settings:

```python
# Add the authentication backend
AUTHENTICATION_BACKENDS = [
    "lasuite.oidc_login.backends.OIDCAuthenticationBackend",
]

# Authentication to support OIDC silent login flows via the 'silent' query parameter
OIDC_AUTHENTICATE_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationRequestView"
OIDC_CALLBACK_CLASS = "lasuite.oidc_login.views.OIDCAuthenticationCallbackView"

# Required OIDC settings
OIDC_RP_CLIENT_ID = "your-client-id"
OIDC_RP_CLIENT_SECRET = "your-client-secret"
OIDC_OP_TOKEN_ENDPOINT = "https://your-provider.com/token"
OIDC_OP_USER_ENDPOINT = "https://your-provider.com/userinfo"
OIDC_OP_LOGOUT_ENDPOINT = "https://your-provider.com/logout"
OIDC_OP_USER_ENDPOINT_FORMAT = "AUTO"  # AUTO, JSON, or JWT, defaults to AUTO

# Optional settings
OIDC_USER_SUB_FIELD = "sub"  # Field to store the OIDC subject identifier, defaults to "sub"
OIDC_USERINFO_FULLNAME_FIELDS = ["first_name", "last_name"]  # Fields used to compute user's full name, defaults to `[]`
OIDC_USERINFO_ESSENTIAL_CLAIMS = ["sub", "last_name"]  # Claims required for user identification, defaults to `[]`
OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True  # Allow fallback to email for user identification
OIDC_CREATE_USER = True  # Automatically create users if they don't exist, defaults to `True`
OIDC_AUTH_REQUEST_FORWARDED_PARAMS = ["login_hint"]  # Forwardable query parameters defaults to `['login_hint'] `
OIDC_OP_LOGOUT_USE_POST = (
    False  # Send the logout request to the OIDC provider with POST instead of GET, defaults to `False`
)
```

### URLs

Include the OIDC URLs in your project's `urls.py`:

```python
from django.urls import include, path

urlpatterns = [
    # Your other URLs
    path("", include("lasuite.oidc_login.urls")),
]
```

## User Model Requirements

Your User model should include the following fields:

1. `sub` - To store the OIDC subject identifier, you may replace this with 
    another field if needed but needs to set the `OIDC_USER_SUB_FIELD` setting
2. `email` - For user identification (especially if fallback to email is enabled)
3. `name` - To store user's full name (computed from fields defined in `OIDC_USERINFO_FULLNAME_FIELDS`)

## Authentication Flow

1. User is redirected to the OIDC provider login page
2. After successful authentication, the provider redirects back to your app
3. The backend verifies the authentication and:
   - Retrieves an existing user based on the `sub` field or falls back to email
   - Creates a new user if no match is found (when `OIDC_CREATE_USER=True`)
   - Updates user information if needed
4. User is now authenticated in your application

## Logout Functionality

The package includes custom logout views that will properly sign the user out from both your application and the OIDC provider.

When the user calls the `logout/` URL, and an ID token is available in the session (`OIDC_STORE_ID_TOKEN = True`), the user is sent to `OIDC_OP_LOGOUT_ENDPOINT` following the [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specification, with the `id_token_hint`, `state` and `post_logout_redirect_uri` parameters. The OIDC provider then redirects the user to the `logout-callback/` URL, which terminates the Django session and redirects to `LOGOUT_REDIRECT_URL`.

The logout request can be sent to the OIDC provider with two HTTP methods:

- **GET** (default): the user is redirected to the OIDC logout endpoint, with the parameters in the query string.
- **POST** (`OIDC_OP_LOGOUT_USE_POST = True`): the view returns an HTML page with a form automatically submitted to the OIDC logout endpoint, with the parameters in the request body. This avoids exposing the ID token in URLs (browser history, server logs) and URL length limits with large ID tokens.

When using the POST method:

- The form is submitted by an inline script. If your project defines a Content Security Policy with [django-csp](https://django-csp.readthedocs.io/), the request nonce is applied to the script (make sure nonces are enabled for `script-src`). Otherwise, the page displays a "Continue" button to submit the form manually. Your `form-action` directive, if any, must allow the OIDC provider logout endpoint.
- The browser sends a cross-site POST request to the OIDC provider: its session cookie must be set with `SameSite=None`, otherwise the provider may not be able to identify the session to end.
- To customize the page, override the `construct_oidc_logout_form_response` method of `lasuite.oidc_login.views.OIDCLogoutView`.

## Customization

To customize the behavior of the OIDC authentication backend, you can create your own subclass:

```python
from lasuite.oidc_login.backends import OIDCAuthenticationBackend


class CustomOIDCAuthenticationBackend(OIDCAuthenticationBackend):
    def get_extra_claims(self, user_info):
        # Add custom claims processing
        claims = super().get_extra_claims(user_info)
        claims["custom_field"] = user_info.get("custom_field")
        return claims

    def post_get_or_create_user(self, user, claims, is_new_user):
        """
        Post-processing after user creation or retrieval.

        Args:
          user (User): The user instance.
          claims (dict): The claims dictionary.
          is_new_user (bool): Indicates if the user was newly created.

        Returns:
        - None

        """
        # Add custom post-processing
```

Then update your `AUTHENTICATION_BACKENDS` setting to use your custom class.
