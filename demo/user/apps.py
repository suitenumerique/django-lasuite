"""User app for the demo project."""

from django.apps import AppConfig


class UserConfig(AppConfig):
    """User app configuration."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "user"
    verbose_name = "Users"
