# Using the healthcheck endpoint

This module provides a `/healthcheck` endpoint meant to be polled by an uptime
monitoring service.

The endpoint is expected to be publicly exposed, so it is protected by an API key passed in the
URL (`GET /healthcheck?key=<api key>`).

## Installation

Add the application to your `INSTALLED_APPS`, which enables the configuration validation.

```python
INSTALLED_APPS = [
    ...
    "lasuite.healthcheck",
]
```

Add the URL to your project's `urls.py`:

```python
from lasuite.healthcheck.urls import urlpatterns as healthcheck_urls

urlpatterns = [
    ...
    *healthcheck_urls,
]
```

## Settings

- `LASUITE_HEALTHCHECK_API_KEY`: the API key expected in the `key` query parameter.
  If not set (or empty), the endpoint denies **all** requests.
  Use a long random value dedicated to this purpose, loaded from an environment variable.
- `LASUITE_HEALTHCHECK_CHECKS`: the list of checks to run, each check being a
  `dict` with a `BACKEND` key (the full path to the check class) and an optional
  `PARAMETERS` key (the keyword arguments used to instantiate it).
  Defaults to the database and cache checks:

```python
LASUITE_HEALTHCHECK_API_KEY="your_api_key"
LASUITE_HEALTHCHECK_CHECKS=[  # optional, defaults to database and cache checks
    {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
    {"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"},
]
```

or, with `django-configurations`:

```python
LASUITE_HEALTHCHECK_API_KEY = values.Value(
    None, environ_name="LASUITE_HEALTHCHECK_API_KEY", environ_prefix=None
)
LASUITE_HEALTHCHECK_CHECKS = JsonValue(  # from lasuite.configurations.values
    [
        {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
        {"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"},
    ],
    environ_name="LASUITE_HEALTHCHECK_CHECKS",
    environ_prefix=None,
)
```

> ⚠️ As the key is passed in the URL, it may appear in access logs (reverse proxy, ingress...).

## Response

| Situation                    | HTTP status | Body                                                  |
|------------------------------|-------------|-------------------------------------------------------|
| Missing or invalid API key   | `403`       | `{"detail": "Invalid API key."}`                      |
| All checks pass              | `200`       | `{"status": "up", "checks": {...}}`                   |
| At least one check fails     | `503`       | `{"status": "down", "checks": {...}}`                 |

Example of a failing response:

```json
{
  "status": "down",
  "checks": {
    "database": {"status": "up", "duration_ms": 2},
    "cache": {"status": "down", "error": "ConnectionError", "duration_ms": 5003},
    "frontend": {"status": "up", "duration_ms": 41}
  }
}
```

The error message is only exposed for `HealthCheckError` exceptions. For any other
exception, only the exception class name is returned, the full traceback is logged.

The endpoint accepts `GET` and `HEAD` requests and is never cached.

## Available checks

### Database

path: `lasuite.healthcheck.checks.DatabaseHealthCheck`
parameters:
    - `alias`: the database alias. Default `"default"`
    - `name`: the check name in the response. Default `"database"`

Runs a `SELECT 1` on the database.

### Cache

path: `lasuite.healthcheck.checks.CacheHealthCheck`
parameters:
    - `alias`: the cache alias. Default `"default"`
    - `name`: the check name in the response. Default `"cache"`

Writes, reads back and deletes a value in the cache. When the cache is backed by
Redis, this checks Redis is up and writable, whatever the cache backend used
(`django-redis`, Django native Redis cache...).

### HTTP (e.g. frontend)

path: `lasuite.healthcheck.checks.HttpHealthCheck`
parameters:
    - `url`: the URL to request. Required
    - `timeout`: the request timeout in seconds. Default `5`
    - `expected_status`: the expected response status code. Default `200`
    - `name`: the check name in the response. Default `"http"`

Example to check the frontend:

```python
LASUITE_HEALTHCHECK_CHECKS = [
    {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
    {"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"},
    {
        "BACKEND": "lasuite.healthcheck.checks.HttpHealthCheck",
        "PARAMETERS": {"name": "frontend", "url": "https://app.example.com/"},
    },
]
```

Check names must be unique: use the `name` parameter to use the same check twice
(e.g. two databases).

## Writing your own check

Inherit from `lasuite.healthcheck.checks.BaseHealthCheck`, define a `name` and implement
`check()`: it must return nothing when the service is healthy and raise an exception
otherwise. Raise a `HealthCheckError` to expose a (non sensitive) message in the response.

Checks are instantiated when the application starts, to validate the configuration:
`__init__` must only store its parameters and must not perform any I/O (network call,
database query...). The instances are then reused for all the requests: `check()` must not
store any per-request state on the instance.

```python
from lasuite.healthcheck.checks import BaseHealthCheck
from lasuite.healthcheck.exceptions import HealthCheckError

from core.services.search import get_opensearch_client


class OpenSearchHealthCheck(BaseHealthCheck):
    name = "opensearch"

    def __init__(self, timeout=5, **kwargs):
        super().__init__(**kwargs)
        self.timeout = timeout

    def check(self):
        if not get_opensearch_client().ping(request_timeout=self.timeout):
            raise HealthCheckError("OpenSearch did not answer to ping")
```

Then add it to the settings:

```python
LASUITE_HEALTHCHECK_CHECKS = [
    {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
    {"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"},
    {"BACKEND": "core.health_checks.OpenSearchHealthCheck", "PARAMETERS": {"timeout": 2}},
]
```

Checks are run sequentially, this might need improvement.
