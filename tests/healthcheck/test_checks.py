"""Tests for the health checks provided by the healthcheck module."""

from unittest import mock

import pytest
import requests
import responses
from django.core.cache import caches

from lasuite.healthcheck.checks import (
    BaseHealthCheck,
    CacheHealthCheck,
    DatabaseHealthCheck,
    HttpHealthCheck,
)
from lasuite.healthcheck.exceptions import HealthCheckError


def test_base_health_check_requires_name():
    """A health check without name cannot be instantiated."""
    with pytest.raises(ValueError, match="must define a name"):
        BaseHealthCheck()


def test_base_health_check_required_check_definition():
    """
    A health check without a check method cannot be run.
    This is only for coverage, as the BaseHealthCheck is abstract and should not
    be instantiated directly...
    """

    class InvalidHealthCheck(BaseHealthCheck):
        name = "invalid"

    with pytest.raises(NotImplementedError):
        InvalidHealthCheck().check()


def test_base_health_check_name_override():
    """The name parameter overrides the class name."""
    assert DatabaseHealthCheck(name="replica").name == "replica"


@pytest.mark.django_db
def test_database_health_check_success():
    """The database check passes on a working database."""
    DatabaseHealthCheck().check()


def test_database_health_check_failure():
    """The database check raises when the database is unreachable."""
    with mock.patch("lasuite.healthcheck.checks.connections") as connections:
        connections.__getitem__.return_value.cursor.side_effect = RuntimeError("unreachable")
        with pytest.raises(RuntimeError):
            DatabaseHealthCheck().check()


def test_cache_health_check_success():
    """The cache check passes and leaves no key behind."""
    cache = caches["default"]
    cache.clear()

    CacheHealthCheck().check()

    assert not cache._cache  # locmem cache storage is empty


def test_cache_health_check_value_not_stored():
    """The cache check fails when the value cannot be read back."""
    with mock.patch("lasuite.healthcheck.checks.caches") as caches_mock:
        cache = caches_mock.__getitem__.return_value
        cache.get.return_value = None

        with pytest.raises(HealthCheckError, match="could not be read back"):
            CacheHealthCheck().check()

    cache.delete.assert_called_once()


@responses.activate
def test_http_health_check_success():
    """The HTTP check passes when the expected status code is returned."""
    responses.get("https://frontend.test/", status=200)

    HttpHealthCheck(url="https://frontend.test/").check()


@responses.activate
def test_http_health_check_custom_expected_status():
    """The expected status code is configurable."""
    responses.get("https://frontend.test/", status=204)

    HttpHealthCheck(url="https://frontend.test/", expected_status=204).check()


@responses.activate
def test_http_health_check_bad_status():
    """The HTTP check fails on an unexpected status code."""
    responses.get("https://frontend.test/", status=502)

    with pytest.raises(HealthCheckError, match="Unexpected status code 502"):
        HttpHealthCheck(url="https://frontend.test/").check()


@responses.activate
def test_http_health_check_timeout():
    """The HTTP check fails on timeout."""
    responses.get("https://frontend.test/", body=requests.Timeout())

    with pytest.raises(HealthCheckError, match="Request timed out"):
        HttpHealthCheck(url="https://frontend.test/").check()


@responses.activate
def test_http_health_check_connection_error():
    """The HTTP check fails when the service is unreachable."""
    responses.get("https://frontend.test/", body=requests.ConnectionError())

    with pytest.raises(HealthCheckError, match="Request failed"):
        HttpHealthCheck(url="https://frontend.test/").check()
