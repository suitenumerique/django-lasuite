"""Fixtures for the healthcheck tests."""

import pytest

from lasuite.healthcheck.services import get_health_checks


@pytest.fixture(name="clear_health_checks_cache")
def clear_health_checks_cache_fixture():
    """Isolate tests from the health checks instances cache."""
    get_health_checks.cache_clear()
    yield
    get_health_checks.cache_clear()
