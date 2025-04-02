# Using the OIDC Authentication Backend to request a resource server

Once your project is configured with the OIDC authentication backend, you can use it to request resources from a resource server. This guide will help you set up and use the `ResourceServerBackend` for token introspection and secure API access.

## Configuration

You need to follow the steps from [how-to-use-oidc-backend.md](how-to-use-oidc-backend.md)

## Additional Settings for Resource Server Communication

To enable your application to communicate with protected resource servers, you'll need to configure token storage in your Django settings:

```python
# Store OIDC tokens in the session
OIDC_STORE_ACCESS_TOKEN = True  # Store the access token in the session
OIDC_STORE_REFRESH_TOKEN = True  # Store the encrypted refresh token in the session

# Required for refresh token encryption
OIDC_STORE_REFRESH_TOKEN_KEY = "your-32-byte-encryption-key=="  # Must be a valid Fernet key (32 url-safe base64-encoded bytes)
```

### Purpose of Each Setting

1. **`OIDC_STORE_ACCESS_TOKEN`**: When set to `True`, the access token received from the OIDC provider will be stored in the user's session. This token is required for making authenticated requests to protected resource servers.

2. **`OIDC_STORE_REFRESH_TOKEN`**: When set to `True`, enables storing the refresh token in the user's session. The refresh token allows your application to request a new access token when the current one expires without requiring user re-authentication.

3. **`OIDC_STORE_REFRESH_TOKEN_KEY`**: This is a cryptographic key used to encrypt the refresh token before storing it in the session. This provides an additional layer of security since refresh tokens are sensitive credentials that can be used to obtain new access tokens.

## Generating a Secure Refresh Token Key

You can generate a secure Fernet key using Python:

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())  # Add this value to your settings
```

## Using the Stored Tokens

Once you have configured these settings, your application can use the stored tokens to make authenticated requests to resource servers:

```python
import requests
from django.http import JsonResponse

def call_resource_server(request):
    # Get the access token from the session
    access_token = request.session.get('oidc_access_token')
    
    if not access_token:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    # Make an authenticated request to the resource server
    response = requests.get(
        'https://resource-server.example.com/api/resource',
        headers={'Authorization': f'Bearer {access_token}'},
    )
    
    return JsonResponse(response.json())
```

## Token Refresh management

### View Based Token Refresh (via decorator)

Request the access token refresh only on specific views using the `refresh_oidc_access_token` decorator:

```python
from lasuite.oidc_login.decorators import refresh_oidc_access_token

class SomeViewSet(GenericViewSet):
    
    @method_decorator(refresh_oidc_access_token)
    def some_action(self, request):
        # Your action logic here
        
        # The call to the resource server
        access_token = request.session.get('oidc_access_token')
        requests.get(
            'https://resource-server.example.com/api/resource',
            headers={'Authorization': f'Bearer {access_token}'},
        )
```

This will trigger the token refresh process only when the `some_action` method is called. 
If the access token is expired, it will attempt to refresh it using the stored refresh token.

### Automatic Token Refresh (via middleware)

You can also use the `RefreshOIDCAccessToken` middleware to automatically refresh expired tokens:

```python
# Add to your MIDDLEWARE setting
MIDDLEWARE = [
    # Other middleware...
    'lasuite.oidc_login.middleware.RefreshOIDCAccessToken',
]
```

This middleware will:
1. Check if the current access token is expired
2. Use the stored refresh token to obtain a new access token
3. Update the session with the new token
4. Continue processing the request with the fresh token

If token refresh fails, the middleware will return a 401 response with a `refresh_url` header to redirect the user to re-authenticate.

