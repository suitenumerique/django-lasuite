"""Throttling for DRF."""

from logging import getLogger

from django.conf import settings
from django.utils.module_loading import import_string
from rest_framework.throttling import ScopedRateThrottle

logger = getLogger("lasuite.drf.throttling")


def simple_logger_throttle_failure(message):
    """Log a warning message when a throttle fails."""
    logger.warning(message)


def monitored_throttle_failure(message):
    """Import custom callback if existing or use the simple logger."""
    callback_path = getattr(settings, "MONITORED_THROTTLE_FAILURE_CALLBACK", None)
    if callback_path is None:
        simple_logger_throttle_failure(message)
        return

    callback = import_string(callback_path)
    callback(message)


class MonitoredThrottleMixin:
    """Mixin for monitored throttles."""

    def throttle_failure(self):
        """Log when a failure occurs to detect rate limiting issues."""
        monitored_throttle_failure(f"Rate limit exceeded for scope {self.scope}")
        return super().throttle_failure()


class MonitoredScopedRateThrottle(MonitoredThrottleMixin, ScopedRateThrottle):
    """Throttle for the monitored scoped rate throttle."""
