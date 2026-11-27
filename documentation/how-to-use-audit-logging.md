# Audit logging

`lasuite.future.logging.audit` emits one Elastic Common Schema (ECS) JSON record per event
through Python's `audit` logger. The audit app connects Django's successful
login, failed login, and logout signals. You can also audit selected DRF
actions, Django admin writes, and operations in service code.

## Configure Django

Install a version of Django LaSuite that includes the audit app.

```sh
pip install 'django-lasuite[future-audit]'
```

Add `"lasuite.future.logging.audit"` to `INSTALLED_APPS` alongside Django's auth app.
Add `"lasuite.future.logging.audit.request.AuditLogMiddleware"` immediately after
`"dockerflow.django.middleware.DockerflowMiddleware"` in `MIDDLEWARE`.
If Dockerflow is already configured, use the existing entry. The audit app
requires no database migrations of its own.

Give the service a name and merge these entries into your logging settings.

```python
AUDIT_LOG_SERVICE_NAME = "dictaphone"
AUDIT_LOG_DATA_STREAM_NAMESPACE = "default"  # Optional. Use a value without hyphens.

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "audit_json": {"()": "lasuite.future.logging.audit.formatter.AuditJsonFormatter"},
    },
    "handlers": {
        "audit_console": {
            "class": "logging.StreamHandler",
            "formatter": "audit_json",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "audit": {
            "handlers": ["audit_console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
```

The middleware generates a request ID and adds an `X-Request-ID` response
header when the response has no such header. Set
`REQUEST_ID_TRUST_HEADER = True` only if your ingress overwrites the incoming
request ID. Use `DOCKERFLOW_REQUEST_ID_HEADER_NAME` to change the header.
The audit event and Dockerflow's request summary use the same ID.
The client IP comes from `REMOTE_ADDR` by default. Set
`REST_FRAMEWORK["NUM_PROXIES"]` to the number of trusted proxies if they
manage the `X-Forwarded-For` chain.

## Register target fields and authentication methods

Create `audit_registry.py` in an installed app. Django LaSuite discovers it
at startup. For example, in Dictaphone's `core/audit_registry.py`:

```python
from lasuite.future.logging import audit

from .authentication.backends import OIDCAuthenticationBackend
from .models import File

audit.register(File, fields=("upload_state",), admin_values=("upload_state",))
audit.register_auth_method(OIDCAuthenticationBackend, "oidc")
```

A model target is identified by its model name and primary key. Use
`fields` to add safe attributes to the target, and `admin_values` to
record changes to specific field values in the admin. For an access grant or
similar model, `user_target="user"` also identifies the account affected.
The account appears under `user.target`. When it has an OIDC subject, the
event records it in `lasuite.user_target.sub`.

## Audit operations

Put `AuditViewMixin` before the DRF base class on your existing viewset.
For example, a file viewset can declare:

```python
from lasuite.future.logging import audit
from rest_framework import viewsets


class FileViewSet(audit.AuditViewMixin, viewsets.ModelViewSet):
    audit_actions = {"create": "file.create", "destroy": "file.delete"}
    # Keep the viewset's queryset, serializers, and permissions here.
```

For a custom route, add `audit_action="file.upload.complete"` to its DRF
`@action(...)` decorator. The mixin records the HTTP status and derives the
outcome from it. It captures objects retrieved through object permission
checks. Set `self.audit_target` in a custom action or after creation when
the view needs to supply the affected object.

To audit writes through Django's default admin site, replace
`"django.contrib.admin"` in `INSTALLED_APPS` with
`"lasuite.future.logging.audit.apps.AuditedAdminConfig"`. Keep the `admin.site.urls` route.
If you use `lasuite.admin` for header colors, keep it in `INSTALLED_APPS`.

Use `audit.log()` directly from a service, plain Django view, or worker.
For example, after a worker completes a transcription:

```python
from lasuite.future.logging import audit

audit.log("file.transcription.complete", target=file)
```

During a request, the middleware supplies the request context automatically.
Pass `request=request` when you have a DRF request and want the authenticator
included. Outside a request, the default actor is the system.

Use stable action names and allow-list details. Registered values, custom
details, and DRF error messages can appear verbatim in the output, so keep
credentials, signed URLs, and file or transcript contents out of these fields.

## Verify the setup

Trigger an audited action and look for its name in `event.action` in the JSON
log. For HTTP requests, compare `http.request.id` with the response header.
In tests, use `lasuite.future.logging.audit.testing.capture_audit()` to collect event
documents inside a `with` block.

## Use with FastAPI or another Python application

Install `django-lasuite` for standalone logging. The base package installs
Django, and the standalone logger runs without Django settings. Set
`AUDIT_LOG_SERVICE_NAME` in the environment and apply the logging dictionary
above with `logging.config.dictConfig(LOGGING)`. Use `RequestContext` to pass
HTTP metadata from your framework. For example, in a FastAPI handler:

```python
from fastapi import Request

from lasuite.future.logging import audit


def audit_document_read(request: Request, document_id: str, user_id: str) -> None:
    audit.log(
        "document.read",
        request=audit.RequestContext(
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
        ),
        actor={"id": user_id},
        target={"id": document_id, "sub_type": "document"},
    )
```
