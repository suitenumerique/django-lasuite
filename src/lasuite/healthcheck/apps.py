"""Healthcheck application configuration."""

from django.apps import AppConfig


class HealthcheckConfig(AppConfig):
    """Register the healthcheck system checks and validate the configuration."""

    name = "lasuite.healthcheck"
    label = "lasuite_healthcheck"

    def ready(self):
        """
        Register the Django system checks and validate the healthcheck configuration.

        Raising here prevents the application from starting with a broken
        configuration, even with WSGI/ASGI servers which do not run the system checks.
        """
        super().ready()

        from . import django_checks  # noqa: F401, PLC0415
        from .services import get_health_checks  # noqa: PLC0415

        get_health_checks()  # will raise or simply return the cached checks if valid
