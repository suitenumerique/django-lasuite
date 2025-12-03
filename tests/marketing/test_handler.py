"""Test the marketing handler."""

import pytest
from django.core.exceptions import ImproperlyConfigured

from lasuite.marketing.backends.dummy import DummyBackend
from lasuite.marketing.handler import MarketingHandler


def test_marketing_handler_from_settings(settings):
    """Test the marketing handler from the settings."""
    settings.LASUITE_MARKETING = {
        "BACKEND": "lasuite.marketing.backends.dummy.DummyBackend",
    }
    handler = MarketingHandler()
    assert isinstance(handler(), DummyBackend)


def test_marketing_handler_from_backend():
    """Test the marketing handler from the backend."""
    handler = MarketingHandler(
        backend={
            "BACKEND": "lasuite.marketing.backends.dummy.DummyBackend",
        }
    )
    assert isinstance(handler(), DummyBackend)


def test_marketing_backend_no_config(settings):
    """Test the marketing handler when no config set should raise an error."""
    settings.LASUITE_MARKETING = None
    handler = MarketingHandler()
    with pytest.raises(ImproperlyConfigured):
        handler()
