"""
Import every module of the given lasuite applications.

Run it in an environment where only one extra of django-lasuite is installed
to check that this extra declares all the dependencies its application needs:

    uv run --isolated --no-project --with ".[drf]" python -I scripts/check_extra_imports.py drf
"""

import importlib
import pkgutil
import sys

import django
from django.conf import settings
from django.core.management.utils import get_random_secret_key

urlpatterns = []


def setup_django(apps):
    """Configure a minimal Django project with the given lasuite applications installed."""
    installed_apps = [
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
    ]
    # Only applications with models must be registered to be importable.
    if "malware_detection" in apps:
        installed_apps.append("lasuite.malware_detection")
    settings.configure(
        INSTALLED_APPS=installed_apps,
        DATABASES={},
        ROOT_URLCONF=__name__,
        SECRET_KEY=get_random_secret_key(),
    )
    django.setup()


def iter_module_names(app):
    """Yield the name of the application package and of all its submodules, migrations excluded."""
    package = importlib.import_module(f"lasuite.{app}")
    yield package.__name__
    for module in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
        if ".migrations" not in module.name:
            yield module.name


def main(apps):
    """Import all the modules of the given applications and report the failures."""
    setup_django(apps)
    failures = []
    for app in apps:
        try:
            module_names = list(iter_module_names(app))
        except ImportError as error:
            failures.append(f"lasuite.{app}: {error!r}")
            continue
        for module_name in module_names:
            try:
                importlib.import_module(module_name)
            except Exception as error:  # noqa: BLE001
                failures.append(f"{module_name}: {error!r}")
        print(f"lasuite.{app}: {len(module_names)} modules checked")

    if failures:
        print("Import failures:", *failures, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:  # noqa: PLR2004
        sys.exit(f"usage: {sys.argv[0]} APP [APP ...]")
    sys.exit(main(sys.argv[1:]))
