"""Custom Django admin site application configuration."""

from django.contrib.admin.apps import AdminConfig


class LaSuiteAdminConfig(AdminConfig):
    """Declare our custom Django admin site."""

    default_site = "admin.sites.LaSuiteAdminSite"
