# Using the OIDC Authentication Backend

This guide explains how to integrate and configure the `OIDCAuthenticationBackend` in your Django project for OpenID Connect (OIDC) authentication.

## Installation

1. Ensure you have the necessary packages installed:

```bash
pip install "django-lasuite[oidc-login]"
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
OIDC_OP_LOGOUT_USE_POST = False  # Send the logout request with POST instead of GET, defaults to `False`
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

If the callback url is hit again with a `state` parameter that is no longer in
the session (e.g. the browser refreshed or replayed the callback url, or the
identity provider sent a duplicate redirect after the first request already
consumed the state), the login is aborted gracefully: the user is redirected
to the failure url (`success_url` instead when already authenticated) rather
than receiving an error page.

A silent login (`?silent=true`) sends `prompt=none` to the identity provider.
If the user has no SSO session, the provider answers with an error such as
`login_required`. The user is then redirected to the `next` url (or
`LOGIN_REDIRECT_URL`) and the OIDC data of this attempt is removed from the
session. When the user is anonymous and the session holds nothing else, the
session is flushed. Its record is deleted from the store and the session
cookie is removed, so anonymous visitors don't keep a session after a failed
silent login.

## Logout Functionality

The package includes custom logout views that will properly sign the user out from both your application and the OIDC provider.

When the user calls the `logout/` URL, and an ID token is available in the session (`OIDC_STORE_ID_TOKEN = True`), the user is sent to `OIDC_OP_LOGOUT_ENDPOINT` following the [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specification, with the `id_token_hint`, `state` and `post_logout_redirect_uri` parameters. The OIDC provider then redirects the user to the `logout-callback/` URL, which terminates the Django session and redirects to `LOGOUT_REDIRECT_URL`.

The logout request can be sent to the OIDC provider with two HTTP methods:

- **GET** (default): the user is redirected to the OIDC logout endpoint, with the parameters in the query string.
- **POST** (`OIDC_OP_LOGOUT_USE_POST = True`): the view returns an HTML page with a form automatically submitted to the OIDC logout endpoint, with the parameters in the request body. This avoids exposing the ID token in URLs (browser history, server logs) and URL length limits with large ID tokens.

When using the POST method:

- The page is rendered from a template shipped with the package: add `"lasuite.oidc_login"` to your `INSTALLED_APPS` so Django can find it.
- The form is submitted by an inline script. If your project defines a Content Security Policy with [django-csp](https://django-csp.readthedocs.io/), the request nonce is applied to the script (make sure nonces are enabled for `script-src`). Otherwise, the page displays a "Continue" button to submit the form manually. Your `form-action` directive, if any, must allow the OIDC provider logout endpoint.
- The browser sends a cross-site POST request to the OIDC provider: its session cookie must be set with `SameSite=None`, otherwise the provider may not be able to identify the session to end.
- To customize the page, override the `lasuite/oidc_login/logout_form.html` template in your project, or set `logout_form_template_name` on a subclass of `lasuite.oidc_login.views.OIDCLogoutView`. The template context contains `oidc_logout_endpoint`, `parameters` (the form fields) and `csp_nonce`. The page declares the active language in its `lang` attribute, and its "Logout" and "Continue" strings can be translated in your project locale files.

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

## Migrating the users to accounts

A product moving from ProConnect to _accounts_ knows its users by their ProConnect sub.
The `migrate_users_to_accounts` command replaces them by _accounts_ subs, without waiting
for each user to log in. It needs `"lasuite.oidc_login"` in your `INSTALLED_APPS`, and the
users import endpoint of _accounts_:

```python
OIDC_OP_USERS_IMPORT_ENDPOINT = "http://accounts:8000/api/v1.0/o/users-import/"
```

The command authenticates with `OIDC_RP_CLIENT_ID` and `OIDC_RP_CLIENT_SECRET`: the
application of this client must be allowed to "import users" in the _accounts_ admin.

```bash
# Migrate the users, 1000 per request by default
python manage.py migrate_users_to_accounts --batch-size 1000
```

The options are:

- `--batch-size`: the number of users per request, 1000 by default.
- `--max-batches`: stop after this number of batches, to run the command from a cron, see
[Running it from a cron](#running-it-from-a-cron).
- `--dry-run`: report what would be created and updated, without writing anything on
either side.

The users are sent by batches with their sub (`OIDC_USER_SUB_FIELD`) and their email,
the oldest first: by `created_at`, then by primary key. When the user model names this
field otherwise, e.g. `date_joined`, set `created_at_field` in a subclass of the command
(see below).
_accounts_ matches each sub with an _accounts_ user, by sub only, and creates the
unknown ones. The command then stores the returned _accounts_ sub, one transaction per
batch. Run it again after an interruption: the users already migrated keep their sub.

To send only the users which are not migrated yet, store the issuer of the sub next to it,
in the field set by `OIDC_USER_ISSUER_FIELD`. It must be nullable: the existing users have
no issuer when it is added.

```python
OIDC_USER_ISSUER_FIELD = "issuer"
OIDC_OP_URL = "https://accounts.example.com/api/v1.0/o"
```

The command handles the users as follows:

- The users whose issuer is `OIDC_OP_URL` are already migrated: the command does not
send them.
- The others get `OIDC_OP_URL` stored as their issuer, together with their _accounts_
sub.
- This includes the users whose sub already was an _accounts_ sub but who had no issuer:
the command sends them, _accounts_ returns the same sub, and only the issuer is stored.
Their sub does not change.

The users of before this field, and the ones created by the resource server with
`OIDC_RS_CREATE_USER`, have no issuer: they are sent. Without this setting, the command
sends all the users.

Some users are logged as warnings and left unchanged:

- `duplicate of user ...`: their _accounts_ sub already belongs to another user of the
product, e.g. the same person logged in with both subs. Merging them is up to the product.
- `email_conflict`: their sub is unknown to _accounts_, but their email belongs to
another _accounts_ user.
- `invalid`: their sub or email is not valid.

Each product can handle them its own way, e.g. merging the duplicates or leaving out the
users to fix by hand, by overriding `handle_duplicate`, `handle_email_conflict` and
`handle_invalid`: see [Customizing the migration](#customizing-the-migration).

### Running it from a cron

To migrate the users a few at a time, without loading _accounts_, run the command from a
cron with `--max-batches`. It requires `OIDC_USER_ISSUER_FIELD`: the migrated users get
the issuer of _accounts_ and are left out, so each run goes on with the next users.

With the Helm charts of La Suite, add a cron job to the values of the backend:

```yaml
backend:
  cronjobs:
    - name: migrate-users-to-accounts
      schedule: "*/5 * * * *"
      command:
        - "/bin/sh"
        - "-c"
        - python manage.py migrate_users_to_accounts --batch-size 500 --max-batches 1
```

Keep `concurrencyPolicy: Forbid`, the default of the charts: a run slower than the
schedule then delays the next one instead of sending the same users twice. If your
network policies restrict the egress of the cron jobs, allow the host of
`OIDC_OP_USERS_IMPORT_ENDPOINT` on port 443.

To run it once by hand, e.g. with `--dry-run`, create a job from the cron job:

```bash
kubectl create job --from=cronjob/<release>-migrate-users-to-accounts migrate-users-to-accounts-manual
```

Each run writes its counts on the standard output and logs a warning for each user it
could not migrate. These users are never left out, so each run sends them first. A run
fails, with a non-zero exit status, when it migrated nobody while other users are
waiting: the logged users fill its batches and hold back the others. Handle them in the
product, e.g. by storing why on the user from the `handle_*` methods and leaving them out
in `get_users_queryset`, or increase `--batch-size` or `--max-batches`.

Once all the users are migrated, a run finds nobody to send and does not call
_accounts_. Remove the cron job, or keep it at night without `--max-batches` to migrate
the users created by the resource server with `OIDC_RS_CREATE_USER`, which have no
issuer:

```yaml
      schedule: "0 3 * * *"
      command:
        - "/bin/sh"
        - "-c"
        - python manage.py migrate_users_to_accounts --batch-size 500
```

### Customizing the migration

Subclass the command in one of your apps, listed before `"lasuite.oidc_login"` in
`INSTALLED_APPS` to keep the `migrate_users_to_accounts` name, and override:

1. `get_users_queryset()`: the users to send, by default all the users with a sub. With
`OIDC_USER_ISSUER_FIELD`, the users whose issuer is `OIDC_OP_URL` are left out.
2. `update_users(users)`: store the users, their _accounts_ sub already set. By default,
a `bulk_update` of the sub, and of the issuer with `OIDC_USER_ISSUER_FIELD`.
3. `handle_duplicate(user, owner)`: called for a user whose _accounts_ sub
belongs to another user, its owner. Return `True` once the owner no longer holds the
sub, e.g. merged into the user: the user then gets it. By default, `False`.
4. `handle_email_conflict(user)` and `handle_invalid(user)`: handle the users _accounts_
could not match nor create. By default, a warning is logged.

`update_users` and `handle_duplicate` run in the transaction of the batch and are never
called in a dry run. The `handle_email_conflict` and `handle_invalid` methods are called
in a dry run too: check `self.dry_run` before writing anything.

```python
# yourapp/management/commands/migrate_users_to_accounts.py
from lasuite.oidc_login.management.commands.migrate_users_to_accounts import (
    Command as BaseCommand,
)


class Command(BaseCommand):
    def handle_duplicate(self, user, owner):
        merge_users(source=owner, target=user)  # your own logic, deleting the owner
        return True
```
