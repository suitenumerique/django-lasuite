"""Health checks available out of the box."""

import uuid

import requests
from django.core.cache import caches
from django.db import connections

from .exceptions import HealthCheckError


class BaseHealthCheck:
    """
    Base class for all health checks.

    Subclasses must implement `check()`, which returns nothing when the service
    is healthy and raises an exception otherwise. Raise a `HealthCheckError`
    to expose a meaningful (non sensitive) message in the healthcheck response.
    """

    name = None

    def __init__(self, name=None):
        """Initialize the health check, allowing to override its name."""
        self.name = name or self.name
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must define a name")

    def check(self):
        """Check the service health, raise an exception when unhealthy."""
        raise NotImplementedError


class DatabaseHealthCheck(BaseHealthCheck):
    """Check the database answers to a trivial query."""

    name = "database"

    def __init__(self, alias="default", **kwargs):
        """Initialize the check for the given database alias."""
        super().__init__(**kwargs)
        self.alias = alias

    def check(self):
        """Run a `SELECT 1` on the database."""
        with connections[self.alias].cursor() as cursor:
            cursor.execute("SELECT 1")
            if cursor.fetchone() != (1,):
                raise HealthCheckError("Unexpected database response")


class CacheHealthCheck(BaseHealthCheck):
    """
    Check the cache backend (usually Redis) with a write/read/delete round trip.

    Using the Django cache API keeps this check independent from the cache
    backend implementation (django-redis, Django native Redis cache, ...).
    """

    name = "cache"

    def __init__(self, alias="default", **kwargs):
        """Initialize the check for the given cache alias."""
        super().__init__(**kwargs)
        self.alias = alias

    def check(self):
        """Write, read back and delete a unique value in the cache."""
        cache = caches[self.alias]
        key = f"lasuite_healthcheck:{uuid.uuid4().hex}"
        value = uuid.uuid4().hex
        try:
            cache.set(key, value, timeout=10)
            if cache.get(key) != value:
                raise HealthCheckError("Cache value could not be read back")
        finally:
            cache.delete(key)


class HttpHealthCheck(BaseHealthCheck):
    """Check an HTTP service (e.g. the frontend) answers with the expected status code."""

    name = "http"

    def __init__(self, url, timeout=5, expected_status=200, **kwargs):
        """Initialize the check for the given URL."""
        super().__init__(**kwargs)
        self.url = url
        self.timeout = timeout
        self.expected_status = expected_status

    def check(self):
        """Perform a GET request on the URL and check the response status code."""
        try:
            response = requests.get(self.url, timeout=self.timeout)
        except requests.Timeout as err:
            raise HealthCheckError("Request timed out") from err
        except requests.RequestException as err:
            raise HealthCheckError("Request failed") from err

        if response.status_code != self.expected_status:
            raise HealthCheckError(f"Unexpected status code {response.status_code}")
