"""Healthcheck views."""

import hmac

from django.conf import settings
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache

from .services import STATUS_UP, run_health_checks


def is_valid_api_key(provided_key):
    """Compare the provided key to the configured one, in constant time."""
    expected_key = getattr(settings, "LASUITE_HEALTHCHECK_API_KEY", None)
    if not expected_key or not provided_key:
        # An unconfigured key never grants access
        return False
    return hmac.compare_digest(provided_key.encode(), expected_key.encode())


@method_decorator(never_cache, name="dispatch")
class HealthcheckView(View):
    """
    Healthcheck endpoint, meant to be polled by an uptime monitoring service.

    The API key must be provided in the `key` query parameter. Returns a 200
    when all checks pass and a 503 otherwise, along with a JSON report.
    HEAD requests are answered like GET ones.
    """

    http_method_names = ["get", "head"]

    def get(self, request):
        """Run all the configured health checks."""
        if not is_valid_api_key(request.GET.get("key")):
            return JsonResponse({"detail": "Invalid API key."}, status=403)

        report = run_health_checks()
        return JsonResponse(report, status=200 if report["status"] == STATUS_UP else 503)
