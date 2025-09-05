"""Test monitored throtthling."""

import logging

import pytest
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from lasuite.drf.throttling import MonitoredScopedRateThrottle

pytestmark = pytest.mark.django_db


def custom_callback(message):
    """Define custom callback."""
    logging.critical(message)


class TestMonitoredScopedRateThrottle(MonitoredScopedRateThrottle):
    """Test monitored scoped rate throttle."""

    __test__ = False

    TIMER_SECONDS = 0
    THROTTLE_RATES = {"test": "1/min"}


class MockView(APIView):
    """Testing mock view."""

    throttle_classes = (TestMonitoredScopedRateThrottle,)
    throttle_scope = "test"

    def get(self, request):
        """Return dummy response."""
        return Response("foo")


def test_monitored_scoped_rate_throttle(caplog):
    """Test the monitored scoped rate throttle."""
    factory = APIRequestFactory()
    request = factory.get("/")
    for _ in range(4):
        response = MockView.as_view()(request)
    assert "Rate limit exceeded for scope test" in caplog.text
    for record in caplog.records:
        assert record.levelname == "WARNING"
    assert response.status_code == 429


def test_monitored_scoped_rate_throttle_custom_callback(caplog, settings):
    """Test the monitored scoped rate throttle with a custom callback."""
    settings.MONITORED_THROTTLE_FAILURE_CALLBACK = "tests.drf.test_throttling.custom_callback"
    factory = APIRequestFactory()
    request = factory.get("/")
    for _ in range(4):
        response = MockView.as_view()(request)
    assert "Rate limit exceeded for scope test" in caplog.text
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert response.status_code == 429
