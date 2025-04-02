"""User customization application."""

from django.apps import AppConfig


class UserConfig(AppConfig):
    """Configuration class for the user app."""

    name = "test_project.user"
    verbose_name = "User manager"
    app_label = "user"
