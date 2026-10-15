"""Healthcheck services: health checks instantiation from the settings and execution."""

import functools
import logging
import time

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from .checks import BaseHealthCheck
from .exceptions import HealthCheckError

logger = logging.getLogger(__name__)

STATUS_UP = "up"
STATUS_DOWN = "down"

DEFAULT_CHECKS = [
    {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
    {"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"},
]


def create_health_check(backend, /, **parameters):
    """
    Instantiate the health check class `backend` (dotted path) with the given parameters.

    Raises ImproperlyConfigured when the class cannot be imported or instantiated.
    """
    try:
        klass = import_string(backend)
    except ImportError as e:
        raise ImproperlyConfigured(f"Could not find health check {backend!r}: {e}") from e

    if not (isinstance(klass, type) and issubclass(klass, BaseHealthCheck)):
        raise ImproperlyConfigured(f"Health check {backend!r} must inherit from BaseHealthCheck")

    try:
        return klass(**parameters)
    except (TypeError, ValueError) as e:
        raise ImproperlyConfigured(f"Could not instantiate health check {backend!r}: {e}") from e


@functools.cache
def get_health_checks():
    """
    Return the health checks configured in `settings.LASUITE_HEALTHCHECK_CHECKS`.

    The instances are cached for the process lifetime (exceptions are not cached),
    and shared between requests.

    Raises ImproperlyConfigured when the configuration is invalid.
    """
    configurations = getattr(settings, "LASUITE_HEALTHCHECK_CHECKS", DEFAULT_CHECKS)
    health_checks = []
    try:
        for configuration in configurations:
            parameters = configuration.get("PARAMETERS", {})
            health_checks.append(create_health_check(configuration["BACKEND"], **parameters))
    except (AttributeError, KeyError, TypeError) as err:
        raise ImproperlyConfigured(f"settings.LASUITE_HEALTHCHECK_CHECKS bad definition: {err!r}") from err

    names = [health_check.name for health_check in health_checks]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ImproperlyConfigured(
            f"Health check names must be unique, duplicated: {', '.join(duplicates)}. "
            'Use the "name" parameter to distinguish them.'
        )
    return tuple(health_checks)


def run_health_check(health_check):
    """Run a single health check and return its result."""
    start = time.monotonic()
    try:
        health_check.check()
    except HealthCheckError as err:
        logger.error("Health check %s failed: %s", health_check.name, err)
        result = {"status": STATUS_DOWN, "error": str(err)}
    except Exception as err:
        # Unexpected errors may contain sensitive details (hosts, credentials...),
        # only expose the exception type.
        logger.exception("Health check %s failed", health_check.name)
        result = {"status": STATUS_DOWN, "error": err.__class__.__name__}
    else:
        result = {"status": STATUS_UP}
    result["duration_ms"] = round((time.monotonic() - start) * 1000)
    return result


def run_health_checks():
    """Run all the configured health checks and return the health report."""
    checks = {health_check.name: run_health_check(health_check) for health_check in get_health_checks()}
    is_healthy = all(result["status"] == STATUS_UP for result in checks.values())
    return {"status": STATUS_UP if is_healthy else STATUS_DOWN, "checks": checks}
