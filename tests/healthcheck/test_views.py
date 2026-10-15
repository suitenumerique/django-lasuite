"""Tests for the healthcheck endpoint."""

import pytest
import responses

pytestmark = pytest.mark.django_db


@pytest.fixture(name="api_key")
def api_key_fixture(settings):
    """Configure the healthcheck API key."""
    settings.LASUITE_HEALTHCHECK_API_KEY = "synthetic-test-api-key"
    return settings.LASUITE_HEALTHCHECK_API_KEY


@pytest.mark.parametrize("key", [None, "", "wrong-key"])
def test_healthcheck_invalid_key(client, api_key, key):
    """Requests without the right key are rejected without running the checks."""
    response = client.get(f"/healthcheck?key={key}")

    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid API key."}


@pytest.mark.parametrize("configured_key", [None, ""])
def test_healthcheck_no_configured_key(client, settings, configured_key):
    """When no key is configured, the endpoint denies all requests."""
    settings.LASUITE_HEALTHCHECK_API_KEY = configured_key

    assert client.get("/healthcheck?key=").status_code == 403
    assert client.get("/healthcheck?key=None").status_code == 403


def test_healthcheck_default_checks(client, api_key):
    """By default, the database and the cache are checked."""
    response = client.get(f"/healthcheck?key={api_key}")

    assert response.status_code == 200
    assert response["Content-Type"] == "application/json"
    assert "no-store" in response["Cache-Control"]
    content = response.json()
    database_duration = content["checks"]["database"]["duration_ms"]
    cache_duration = content["checks"]["cache"]["duration_ms"]
    assert content == {
        "status": "up",
        "checks": {
            "database": {"status": "up", "duration_ms": database_duration},  # don't want to mock...
            "cache": {"status": "up", "duration_ms": cache_duration},  # don't want to mock...
        },
    }


@responses.activate
def test_healthcheck_custom_checks(clear_health_checks_cache, client, api_key, settings):
    """Projects can configure their own list of checks, with parameters."""
    responses.get("https://frontend.test/", status=200)
    settings.LASUITE_HEALTHCHECK_CHECKS = [
        {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
        {
            "BACKEND": "lasuite.healthcheck.checks.HttpHealthCheck",
            "PARAMETERS": {"name": "frontend", "url": "https://frontend.test/"},
        },
    ]

    response = client.get(f"/healthcheck?key={api_key}")

    assert response.status_code == 200
    content = response.json()
    database_duration = content["checks"]["database"]["duration_ms"]  # don't want to mock...
    frontend_duration = content["checks"]["frontend"]["duration_ms"]  # don't want to mock...
    assert content == {
        "status": "up",
        "checks": {
            "database": {"status": "up", "duration_ms": database_duration},
            "frontend": {"status": "up", "duration_ms": frontend_duration},
        },
    }


def test_healthcheck_failure(clear_health_checks_cache, client, api_key, settings):
    """A failing check makes the endpoint return a 503 with the error message."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [
        {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
        {"BACKEND": "test_project.health_checks.FailingHealthCheck"},
    ]

    response = client.get(f"/healthcheck?key={api_key}")

    assert response.status_code == 503
    content = response.json()
    database_duration = content["checks"]["database"]["duration_ms"]  # don't want to mock...
    failing_duration = content["checks"]["failing"]["duration_ms"]  # don't want to mock...

    assert content == {
        "status": "down",
        "checks": {
            "database": {"status": "up", "duration_ms": database_duration},
            "failing": {"status": "down", "error": "Service unavailable", "duration_ms": failing_duration},
        },
    }


def test_healthcheck_unexpected_error_not_leaked(clear_health_checks_cache, client, api_key, settings, caplog):
    """Unexpected exceptions details are logged but not exposed in the response."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [
        {"BACKEND": "test_project.health_checks.CrashingHealthCheck"},
    ]

    response = client.get(f"/healthcheck?key={api_key}")

    assert response.status_code == 503
    content = response.json()
    duration_ms = content["checks"]["crashing"]["duration_ms"]  # don't want to mock...
    assert content == {
        "status": "down",
        "checks": {"crashing": {"status": "down", "error": "ConnectionError", "duration_ms": duration_ms}},
    }
    assert "Health check crashing failed" in caplog.text


def test_healthcheck_head(clear_health_checks_cache, client, api_key, settings):
    """HEAD requests (used by some monitoring tools) return the same status code."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [
        {"BACKEND": "test_project.health_checks.FailingHealthCheck"},
    ]

    response = client.head(f"/healthcheck?key={api_key}")

    assert response.status_code == 503
    assert response.content == b""


def test_healthcheck_post_not_allowed(client, api_key):
    """Only GET and HEAD are allowed."""
    assert client.post(f"/healthcheck?key={api_key}").status_code == 405
