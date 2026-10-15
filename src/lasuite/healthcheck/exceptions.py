"""Healthcheck exceptions."""


class HealthCheckError(Exception):
    """
    Raised by a health check when the checked service is not healthy.

    The message is exposed in the healthcheck response, it must not contain
    any sensitive information.
    """
