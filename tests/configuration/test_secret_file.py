"""Tests for SecretFileValue."""

import os

import pytest

from lasuite.configuration.values import SecretFileValue

FILE_SECRET_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_secret")


@pytest.fixture(autouse=True)
def _mock_clear_env(monkeypatch):
    """Reset environment variables."""
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY", raising=False)
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY_PATH", raising=False)


@pytest.fixture
def _mock_secret_key_env(monkeypatch):
    """Set secret key in environment variable."""
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY", "TestSecretInEnv")


@pytest.fixture
def _mock_secret_key_file_env(monkeypatch):
    """Set secret key path in environment variable."""
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY_FILE", FILE_SECRET_PATH)


@pytest.fixture
def _mock_secret_key_path_env(monkeypatch):
    """Set secret key path in environment variable with another `file_suffix`."""
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY_PATH", FILE_SECRET_PATH)


def test_secret_default():
    """Test call with no environment variable."""
    value = SecretFileValue("DefaultTestSecret")
    assert value.setup("TEST_SECRET_KEY") == "DefaultTestSecret"


@pytest.mark.usefixtures("_mock_secret_key_env")
def test_secret_in_env():
    """Test call with secret key environment variable."""
    value = SecretFileValue("DefaultTestSecret")
    assert os.environ["DJANGO_TEST_SECRET_KEY"] == "TestSecretInEnv"
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInEnv"


@pytest.mark.usefixtures("_mock_secret_key_file_env")
def test_secret_in_file():
    """Test call with secret key file environment variable."""
    value = SecretFileValue("DefaultTestSecret")
    assert os.environ["DJANGO_TEST_SECRET_KEY_FILE"] == FILE_SECRET_PATH
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInFile"


def test_secret_default_suffix():
    """Test call with no environment variable and non default `file_suffix`."""
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert value.setup("TEST_SECRET_KEY") == "DefaultTestSecret"


@pytest.mark.usefixtures("_mock_secret_key_env")
def test_secret_in_env_suffix():
    """Test call with secret key environment variable and non default `file_suffix`."""
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert os.environ["DJANGO_TEST_SECRET_KEY"] == "TestSecretInEnv"
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInEnv"


@pytest.mark.usefixtures("_mock_secret_key_path_env")
def test_secret_in_file_suffix():
    """Test call with secret key file environment variable and non default `file_suffix`."""
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert os.environ["DJANGO_TEST_SECRET_KEY_PATH"] == FILE_SECRET_PATH
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInFile"
