"""Django system checks for the healthcheck module."""

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from .services import get_health_checks


@checks.register(checks.Tags.security)
def check_healthcheck_api_key(app_configs, **kwargs):
    """Warn when the healthcheck API key is not configured."""
    api_key = getattr(settings, "LASUITE_HEALTHCHECK_API_KEY", "MISSING")
    if not api_key:
        return [
            checks.Warning(
                "settings.LASUITE_HEALTHCHECK_API_KEY is set to None or empty, "
                "the healthcheck endpoint will deny all requests.",
                id="lasuite_healthcheck.W002",
            )
        ]

    if api_key == "MISSING":
        return [
            checks.Warning(
                "settings.LASUITE_HEALTHCHECK_API_KEY is not set, while the lasuite.healthcheck module is installed.",
                id="lasuite_healthcheck.W001",
            )
        ]

    return []


@checks.register()
def check_healthcheck_configuration(app_configs, **kwargs):
    """Report an error when the healthcheck configuration is invalid."""
    try:
        get_health_checks()
    except ImproperlyConfigured as err:
        return [
            checks.Error(
                f"Invalid settings.LASUITE_HEALTHCHECK_CHECKS: {err}",
                id="lasuite_healthcheck.E001",
            )
        ]

    return []
