# Django La Suite Demo - Resource Server Client

This demo application shows how to use `django-lasuite` to build an OIDC client
that authenticates users and then consumes a protected resource server API.

## What it does

1. **OIDC Login**: Users authenticate via an external OIDC provider using
   `lasuite.oidc_login`.
2. **Token Storage**: Access tokens are stored in the Django session so they can
   be reused.
3. **Token Refresh**: The `@refresh_oidc_access_token` decorator ensures the
   access token is refreshed automatically before calling the resource server.
4. **Resource Server Client**: A view fetches the user's access token from the
   session and uses it to call `/api/v1.0/users/me/` on an external resource
   server.

## Project layout

```
demo/
├── demo/
│   ├── settings.py          # All OIDC settings are configurable here
│   ├── urls.py
│   └── wsgi.py
├── client/
│   ├── views.py             # resource_server_me view (with token refresh)
│   ├── urls.py
│   └── templates/client/
├── user/
│   └── models.py            # Custom User model (sub, name, email)
├── Dockerfile               # Demo app image
├── compose.yaml             # Docker Compose stack
├── entrypoint.sh            # Migrations + runserver
├── mock_resource_server.py  # Lightweight mock RS for testing
├── .env.example             # Example environment variables
└── manage.py
```

## Quick start (Docker Compose)

The Docker Compose stack includes:

- **web** — the Django demo app
- **mock-resource-server** — a lightweight mock API that responds to
  `/api/v1.0/users/me/`

### 1. Configure environment variables

```bash
cd demo
cp .env.example .env
# Edit .env and fill in your OIDC provider details.
```

If you only want to test the resource-server client call without a real OIDC
provider, leave the OIDC endpoints empty. The login button won't work, but you
can still verify the HTTP request pattern.

> **Note:** `OIDC_STORE_REFRESH_TOKEN_KEY` must be exactly 32 bytes long.
> The default value is only suitable for local development.

### 2. Build and run

```bash
docker compose up --build
```

### 3. Try it out

1. Open http://localhost:8000/
2. If you configured a real OIDC provider, click **Log in with OIDC**
3. After authentication, click **Call Resource Server /api/v1.0/users/me/**

The demo app will use the (possibly refreshed) access token stored in the Django
session to call the resource server. By default it points at the mock resource
server (`http://mock-resource-server:8080`).

### Override the resource server

To point at a real resource server, edit `.env`:

```bash
RESOURCE_SERVER_BASE_URL=https://your-resource-server.example.com
```

Then restart:

```bash
docker compose up
```

## Key files

### `client/views.py`

The `resource_server_me` view demonstrates the core pattern. It is decorated
with `@refresh_oidc_access_token` so the access token is kept valid before
making the outbound request:

```python
from lasuite.oidc_login.decorators import refresh_oidc_access_token

@login_required
@refresh_oidc_access_token
def resource_server_me(request):
    access_token = request.session.get("oidc_access_token")
    response = requests.get(
        f"{settings.RESOURCE_SERVER_BASE_URL}/api/v1.0/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    ...
```

The access token is available in the session because `OIDC_STORE_ACCESS_TOKEN`
is set to `True` in `settings.py`.

### `demo/settings.py`

Every OIDC setting is read from an environment variable, so the demo can be
pointed at any OIDC provider and resource server without code changes.

## OIDC settings reference

| Environment Variable | Description |
|----------------------|-------------|
| `OIDC_OP_URL` | OIDC provider base URL |
| `OIDC_OP_AUTHORIZATION_ENDPOINT` | Authorization endpoint |
| `OIDC_OP_TOKEN_ENDPOINT` | Token endpoint |
| `OIDC_OP_USER_ENDPOINT` | UserInfo endpoint |
| `OIDC_OP_LOGOUT_ENDPOINT` | Logout endpoint |
| `OIDC_RP_CLIENT_ID` | Client ID |
| `OIDC_RP_CLIENT_SECRET` | Client secret |
| `OIDC_RP_SCOPES` | Requested scopes (default: `openid email profile`) |
| `OIDC_VERIFY_SSL` | Verify SSL certificates (default: `true`) |
| `OIDC_TIMEOUT` | Request timeout in seconds (default: `10`) |
| `OIDC_STORE_REFRESH_TOKEN_KEY` | Fernet key for encrypting refresh tokens |
| `RESOURCE_SERVER_BASE_URL` | Base URL of the resource server to consume |

---

## Running without Docker (advanced / optional)

If you prefer to run directly on the host, install dependencies first:

```bash
# from the repository root
uv sync --extra dev
# or: pip install -e ".[dev]"
```

Then configure, migrate and run:

```bash
cd demo
cp .env.example .env
# Edit .env with your OIDC provider details

# Export variables from .env to the current shell
export $(grep -v '^#' .env | xargs)

python manage.py migrate
python manage.py runserver
```
