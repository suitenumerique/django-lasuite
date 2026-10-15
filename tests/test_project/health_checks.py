"""Health checks used to test the healthcheck module."""

from lasuite.healthcheck.checks import BaseHealthCheck
from lasuite.healthcheck.exceptions import HealthCheckError


class FailingHealthCheck(BaseHealthCheck):
    """Health check failing with a controlled message."""

    name = "failing"

    def check(self):
        """Fail."""
        raise HealthCheckError("Service unavailable")


class CrashingHealthCheck(BaseHealthCheck):
    """Health check failing with an unexpected exception."""

    name = "crashing"

    def check(self):
        """Crash with a sensitive message."""
        raise ConnectionError("redis://user:secret@redis:6379 unreachable")
