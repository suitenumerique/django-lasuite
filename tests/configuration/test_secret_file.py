"""Tests for SecretFileValue"""

import os

import pytest

from lasuite.configuration.values import SecretFileValue

FILE_SECRET_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_secret")


@pytest.fixture(autouse=True)
def mock_clear_env(monkeypatch):
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY", raising=False)
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("DJANGO_TEST_SECRET_KEY_PATH", raising=False)


@pytest.fixture
def mock_secret_key_env(monkeypatch):
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY", "TestSecretInEnv")


@pytest.fixture
def mock_secret_key_file_env(monkeypatch):
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY_FILE", FILE_SECRET_PATH)


@pytest.fixture
def mock_secret_key_path_env(monkeypatch):
    monkeypatch.setenv("DJANGO_TEST_SECRET_KEY_PATH", FILE_SECRET_PATH)


def test_secret_default():
    value = SecretFileValue("DefaultTestSecret")
    assert value.setup("TEST_SECRET_KEY") == "DefaultTestSecret"


def test_secret_in_env(mock_secret_key_env):
    value = SecretFileValue("DefaultTestSecret")
    assert os.environ["DJANGO_TEST_SECRET_KEY"] == "TestSecretInEnv"
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInEnv"


def test_secret_in_file(mock_secret_key_file_env):
    value = SecretFileValue("DefaultTestSecret")
    assert os.environ["DJANGO_TEST_SECRET_KEY_FILE"] == FILE_SECRET_PATH
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInFile"


def test_secret_default_suffix():
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert value.setup("TEST_SECRET_KEY") == "DefaultTestSecret"


def test_secret_in_env_suffix(mock_secret_key_env):
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert os.environ["DJANGO_TEST_SECRET_KEY"] == "TestSecretInEnv"
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInEnv"


def test_secret_in_file_suffix(mock_secret_key_path_env):
    value = SecretFileValue("DefaultTestSecret", file_suffix="PATH")
    assert os.environ["DJANGO_TEST_SECRET_KEY_PATH"] == FILE_SECRET_PATH
    assert value.setup("TEST_SECRET_KEY") == "TestSecretInFile"
