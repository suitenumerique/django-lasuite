"""Access Django settings and model types when Django is available."""

try:
    from django.apps import apps
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.db import models
except ModuleNotFoundError as error:
    if error.name != "django":
        raise
    apps = settings = models = None


def get_setting(name, default=None):
    """Read a setting from configured Django settings."""
    if settings is not None and settings.configured:
        return getattr(settings, name, default)
    return default


def is_model(value):
    """Tell whether the value is a Django model instance."""
    return models is not None and isinstance(value, models.Model)


def is_queryset(value):
    """Tell whether the value is a Django queryset."""
    return models is not None and isinstance(value, models.QuerySet)


def is_user(value):
    """Tell whether the value is an instance of the configured Django user model."""
    return (
        apps is not None
        and apps.apps_ready
        and is_model(value)
        and apps.is_installed("django.contrib.auth")
        and isinstance(value, get_user_model())
    )
