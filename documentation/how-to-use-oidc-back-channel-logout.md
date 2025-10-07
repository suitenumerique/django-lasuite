# Using the OIDC Authentication Backend With Back-Channel Logout

This guide explains how to integrate and configure the `OIDCBackChannelLogoutView` in your Django project for OpenID Connect (OIDC) authentication.

## Installation

To use the OIDC authentication backend with back-channel logout support, who obviously need to have set up the OIDC authentication backend first. 
If you haven't done so, please refer to the [Using the OIDC Authentication Backend](how-to-use-oidc-backend.md) guide.


## Configuration

### Settings

You need to have the [Using the OIDC Authentication Backend](how-to-use-oidc-backend.md) settings configured first.

Then, add the following to your Django settings:

```python
# A db backed session engine is required to support back-channel logout
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
# OR "django.contrib.sessions.backends.db" if you don't want caching

# New required OIDC settings
OIDC_OP_URL="https://your-provider.com"
```

### URLs

The project OIDC URLs `lasuite.oidc_login.urls` already include the back-channel logout URL,
so you just need to include them in your project's `urls.py` if you haven't done so already:

```python
from django.urls import include, path

urlpatterns = [
    # Your other URLs
    path('', include('lasuite.oidc_login.urls')),
]
```

The back-channel logout endpoint will be available at `<base-URL>/back-channel-logout/`.


### Set up the OIDC Provider accordingly

Make sure to configure your OIDC Provider to send back-channel logout requests 
to your Django application's back-channel logout endpoint.

For instance, in Keycloak, you can set the "Backchannel Logout URL" in the client settings -> "Logout settings":

- Turn off "Front channel logout"
- Set "Backchannel Logout URL" to `<base-URL>/back-channel-logout/` (like http://app-dev:8071/api/v1.0/backchannel-logout/)
- Enable/Disable "Backchannel Logout Session Required" as per your requirements

Note the "Backchannel Logout Session Required" requires the `sid` claim to be sent in the token info at login to be 
able to match session.
