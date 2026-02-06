"""Custom Django admin site for the LaSuite app."""

from django.conf import settings
from django.contrib import admin


class LaSuiteAdminSite(admin.AdminSite):
    """LaSuite custom admin site."""

    def each_context(self, request):
        """Add custom context to the admin site."""
        return super().each_context(request) | {
            "ADMIN_HEADER_BACKGROUND": getattr(settings, "ADMIN_HEADER_BACKGROUND", None),
            "ADMIN_HEADER_COLOR": getattr(settings, "ADMIN_HEADER_COLOR", None),
        }
