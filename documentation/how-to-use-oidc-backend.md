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
    'lasuite.oidc_login.backends.OIDCAuthenticationBackend',
]

# Required OIDC settings
OIDC_RP_CLIENT_ID = "your-client-id"
OIDC_RP_CLIENT_SECRET = "your-client-secret"
OIDC_OP_TOKEN_ENDPOINT = "https://your-provider.com/token"
OIDC_OP_USER_ENDPOINT = "https://your-provider.com/userinfo"
OIDC_OP_LOGOUT_ENDPOINT = "https://your-provider.com/logout"
OIDC_OP_USER_ENDPOINT_FORMAT = "AUTO"  # AUTO, JSON, or JWT

# Optional settings
OIDC_USER_SUB_FIELD = "sub"  # Field to store the OIDC subject identifier, defaults to "sub"
USER_OIDC_FIELDS_TO_FULLNAME = ["first_name", "last_name"]  # Fields used to compute user's full name
USER_OIDC_ESSENTIAL_CLAIMS = ["sub", "last_name"]  # Claims required for user identification
OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = True  # Allow fallback to email for user identification
OIDC_CREATE_USER = True  # Automatically create users if they don't exist
ALLOW_LOGOUT_GET_METHOD = True  # Allow GET method for logout
```

### URLs

Include the OIDC URLs in your project's `urls.py`:

```python
from django.urls import include, path

urlpatterns = [
    # Your other URLs
    path('', include('lasuite.oidc_login.urls')),
]
```

## User Model Requirements

Your User model should include the following fields:

1. `sub` - To store the OIDC subject identifier, you may replace this with 
    another field if needed but needs to set the `OIDC_USER_SUB_FIELD` setting
2. `email` - For user identification (especially if fallback to email is enabled)
3. `name` - To store user's full name (computed from fields defined in `USER_OIDC_FIELDS_TO_FULLNAME`)

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

## Customization

To customize the behavior of the OIDC authentication backend, you can create your own subclass:

```python
from lasuite.oidc_login.backends import OIDCAuthenticationBackend


class CustomOIDCAuthenticationBackend(OIDCAuthenticationBackend):
    def get_extra_claims(self, user_info):
        # Add custom claims processing
        claims = super().get_extra_claims(user_info)
        claims['custom_field'] = user_info.get('custom_field')
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
