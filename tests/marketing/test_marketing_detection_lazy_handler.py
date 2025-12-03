"""Test the marketing lazy handler."""

from lasuite.marketing import marketing
from lasuite.marketing.backends.dummy import DummyBackend


def test_marketing_lazy_handler(settings):
    """Test the marketing lazy handler."""
    settings.LASUITE_MARKETING = {
        "BACKEND": "lasuite.marketing.backends.dummy.DummyBackend",
    }
    assert isinstance(marketing, DummyBackend)
