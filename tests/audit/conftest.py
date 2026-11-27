"""Fixtures for audit logging tests."""

import pytest

from lasuite.audit.testing import capture_audit


@pytest.fixture
def audit_events():
    """Collect events emitted during the test."""
    with capture_audit() as events:
        yield events
