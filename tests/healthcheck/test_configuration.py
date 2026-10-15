"""Tests for the healthcheck configuration validation."""

import pytest
from django.apps import apps
from django.core.exceptions import ImproperlyConfigured

from lasuite.healthcheck.checks import CacheHealthCheck, DatabaseHealthCheck, HttpHealthCheck
from lasuite.healthcheck.django_checks import check_healthcheck_api_key, check_healthcheck_configuration
from lasuite.healthcheck.services import create_health_check, get_health_checks


def test_get_health_checks_default(settings):
    """Without configuration, the database and cache checks are used."""
    del settings.LASUITE_HEALTHCHECK_CHECKS

    health_checks = get_health_checks()

    assert [type(health_check) for health_check in health_checks] == [DatabaseHealthCheck, CacheHealthCheck]


def test_get_health_checks_with_parameters(clear_health_checks_cache, settings):
    """Health checks are instantiated with their parameters."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [
        {
            "BACKEND": "lasuite.healthcheck.checks.HttpHealthCheck",
            "PARAMETERS": {"name": "frontend", "url": "https://frontend.test/", "timeout": 2},
        },
    ]

    (health_check,) = get_health_checks()

    assert isinstance(health_check, HttpHealthCheck)
    assert health_check.name == "frontend"
    assert health_check.timeout == 2


@pytest.mark.parametrize(
    ("checks_setting", "error"),
    [
        ({"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"}, "bad definition: AttributeError"),
        (["lasuite.healthcheck.checks.DatabaseHealthCheck"], "bad definition: AttributeError"),
        ([{"PARAMETERS": {}}], "bad definition: KeyError"),
        (
            [{"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck", "PARAMETERS": ["replica"]}],
            "bad definition: TypeError.*must be a mapping",
        ),
        ([{"BACKEND": "lasuite.healthcheck.checks.Unknown"}], "Could not find health check"),
        ([{"BACKEND": "lasuite.healthcheck.services.get_health_checks"}], "must inherit from BaseHealthCheck"),
        ([{"BACKEND": "lasuite.healthcheck.checks.HttpHealthCheck"}], "Could not instantiate health check"),
        (
            [{"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck", "PARAMETERS": {"unknown": 1}}],
            "Could not instantiate health check",
        ),
        ([{"BACKEND": "lasuite.healthcheck.checks.BaseHealthCheck"}], "Could not instantiate health check"),
        (
            [
                {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
                {"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"},
            ],
            "duplicated: database",
        ),
    ],
)
def test_get_health_checks_invalid_configuration(clear_health_checks_cache, settings, checks_setting, error):
    """Invalid configurations raise ImproperlyConfigured, also reported by the system check."""
    settings.LASUITE_HEALTHCHECK_CHECKS = checks_setting

    with pytest.raises(ImproperlyConfigured, match=error):
        get_health_checks()

    (system_check_error,) = check_healthcheck_configuration(None)
    assert system_check_error.id == "lasuite_healthcheck.E001"
    assert system_check_error.is_serious()


def test_create_health_check():
    """A health check is created from its class path and keyword arguments."""
    health_check = create_health_check(
        "lasuite.healthcheck.checks.HttpHealthCheck", name="frontend", url="https://frontend.test/"
    )

    assert isinstance(health_check, HttpHealthCheck)
    assert health_check.name == "frontend"
    assert health_check.url == "https://frontend.test/"


def test_create_health_check_backend_parameter():
    """A health check parameter named "backend" does not clash with the class path argument."""
    with pytest.raises(ImproperlyConfigured, match="unexpected keyword argument 'backend'"):
        create_health_check("lasuite.healthcheck.checks.DatabaseHealthCheck", backend="other")


def test_get_health_checks_cached(clear_health_checks_cache, settings):
    """Health checks are instantiated once, until the setting changes."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [{"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"}]

    health_checks = get_health_checks()
    assert get_health_checks() is health_checks  # same python object => cached

    settings.LASUITE_HEALTHCHECK_CHECKS = [{"BACKEND": "lasuite.healthcheck.checks.CacheHealthCheck"}]

    get_health_checks.cache_clear()  # clear the cache to force re-evaluation
    (health_check,) = get_health_checks()
    assert isinstance(health_check, CacheHealthCheck)  # same python object => cached


def test_system_check_checks_valid(settings):
    """No error is reported for a valid configuration."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [{"BACKEND": "lasuite.healthcheck.checks.DatabaseHealthCheck"}]

    assert check_healthcheck_configuration(None) == []


def test_app_ready_invalid_configuration(clear_health_checks_cache, settings):
    """The application refuses to start with an invalid configuration."""
    settings.LASUITE_HEALTHCHECK_CHECKS = [{"BACKEND": "lasuite.healthcheck.checks.Unknown"}]

    with pytest.raises(ImproperlyConfigured, match="Could not find health check"):
        apps.get_app_config("lasuite_healthcheck").ready()


def test_system_check_api_key_missing(settings):
    """A warning is emitted when the API key setting is not defined."""
    del settings.LASUITE_HEALTHCHECK_API_KEY

    assert [warning.id for warning in check_healthcheck_api_key(None)] == ["lasuite_healthcheck.W001"]


def test_system_check_api_key_none(settings):
    """A warning is emitted when the API key is explicitly set to None."""
    settings.LASUITE_HEALTHCHECK_API_KEY = None

    assert [warning.id for warning in check_healthcheck_api_key(None)] == ["lasuite_healthcheck.W002"]


def test_system_check_api_key_empty(settings):
    """A warning is emitted when the API key is empty."""
    settings.LASUITE_HEALTHCHECK_API_KEY = ""

    assert [warning.id for warning in check_healthcheck_api_key(None)] == ["lasuite_healthcheck.W002"]


def test_system_check_api_key_defined(settings):
    """No warning is emitted when the API key is defined."""
    settings.LASUITE_HEALTHCHECK_API_KEY = "synthetic-test-api-key"

    assert check_healthcheck_api_key(None) == []
