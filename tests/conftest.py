"""Fixtures for the test suite."""

import django
import pytest
from django.core.files.storage.memory import InMemoryFileNode
from packaging.version import parse


@pytest.fixture(autouse=True)
def patch_inmemoryfilenode():
    """
    Monkeypatch InMemoryFileNode to add 'name' property for Django < 5.2 .

    In Django 5.2+, InMemoryFileNode has a 'name' attribute, but in earlier versions
    it's missing, causing AttributeError in tests.

    As it should only be used for testing, we patch it in tests.
    """
    if parse(django.__version__) < parse("5.2"):
        # Only apply the patch for Django versions before 5.2
        original_init = InMemoryFileNode.__init__

        def patched_init(self, *args, name=None, **kwargs):
            original_init(self, *args, **kwargs)
            # Add name attribute based on path
            self.name = name

        InMemoryFileNode.__init__ = patched_init

        # Restore original method after tests
        yield
        InMemoryFileNode.__init__ = original_init
    else:
        # No need to patch for Django 5.2+
        yield
