"""Test the labels application installation."""

from django.apps import apps


def test_labels_app_is_installed():
    """Install the app so its checks and hooks run."""
    config = apps.get_app_config("labels")

    assert config.name == "lasuite.labels"
    assert config.label == "labels"


def test_labels_app_ships_no_model_yet():
    """The kernel commits must not create any table."""
    config = apps.get_app_config("labels")

    assert list(config.get_models()) == []
