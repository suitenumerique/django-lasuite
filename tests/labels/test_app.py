"""Test the labels application installation."""

from django.apps import apps


def test_labels_app_is_installed():
    """Install the app so its checks and hooks run."""
    config = apps.get_app_config("labels")

    assert config.name == "lasuite.labels"
    assert config.label == "labels"


def test_labels_app_ships_the_three_models():
    """The app persists profiles, dimensions and the audit journal."""
    config = apps.get_app_config("labels")

    assert sorted(model.__name__ for model in config.get_models()) == [
        "LabelAuditEvent",
        "LabelDimension",
        "LabelProfile",
    ]
