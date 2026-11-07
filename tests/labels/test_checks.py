"""Test boot checks for warnings, errors and crash safety."""

import pytest
from django.core.checks import Error
from django.db import OperationalError

from lasuite.labels import compile as labels_compile
from lasuite.labels.checks import check_active_profile, messages_for
from lasuite.labels.compile import CompiledProfile
from lasuite.labels.lattice import Lattice
from lasuite.labels.models import LabelProfile
from lasuite.labels.testing import Violation

from .conftest import build_profile


@pytest.mark.django_db
def test_no_profile_is_a_warning_not_an_error(db):
    """Installing the package before choosing a profile must still boot."""
    messages = check_active_profile()

    assert [message.id for message in messages] == ["labels.W001"]
    assert messages[0].level == 30  # WARNING


@pytest.mark.django_db
def test_a_valid_profile_raises_nothing(profile):
    """The shipped shapes must be accepted at boot."""
    assert check_active_profile() == []


@pytest.mark.django_db
def test_a_profile_without_a_ceiling_is_flagged(db):
    """A ceiling limits what the instance can hold."""
    build_profile(code="no-ceiling", state="active")

    messages = check_active_profile()

    assert [message.id for message in messages] == ["labels.W003"]


@pytest.mark.django_db
def test_a_ceiling_silences_the_warning(profile):
    """Declaring a ceiling is enough."""
    assert check_active_profile() == []


@pytest.mark.django_db
def test_a_broken_lattice_is_an_error(profile, monkeypatch):
    """A profile that does not satisfy the contract must not be used silently."""
    broken = CompiledProfile(
        profile_id=profile.pk,
        code="broken",
        version=1,
        content_hash="x",
        ceiling="DR",
        lattice=profile.to_lattice(),
    )
    monkeypatch.setattr("lasuite.labels.compile.active_profile", lambda **kwargs: broken)
    monkeypatch.setattr(
        "lasuite.labels.checks.check_lattice",
        lambda lattice: [
            __import__("lasuite.labels.testing", fromlist=["Violation"]).Violation("lattice.order", "broken order")
        ],
    )

    messages = check_active_profile()

    assert [message.id for message in messages] == ["labels.E002"]
    assert messages[0].hint == "lattice.order"


@pytest.mark.django_db
def test_an_unmigrated_database_is_not_a_check_failure(monkeypatch):
    """`manage.py check` runs before `migrate` in most pipelines."""

    class Missing:
        """A manager whose table does not exist yet."""

        @staticmethod
        def filter(**kwargs):
            raise OperationalError("no such table")

    monkeypatch.setattr("lasuite.labels.checks.LabelProfile.objects", Missing())

    assert check_active_profile() == []


@pytest.mark.django_db
def test_an_unexpected_error_is_reported(profile, monkeypatch):
    """A bug in the compile path must show up as a check, not as a traceback."""

    def explode(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("lasuite.labels.compile.active_profile", explode)

    messages = check_active_profile()

    assert [message.id for message in messages] == ["labels.E001"]
    assert isinstance(messages[0], Error)


@pytest.mark.django_db
def test_message_levels_are_respected():
    """Warnings do not stop boot."""
    messages = messages_for(
        [
            Violation("lattice.order", "an error"),
            Violation("lattice.atom_budget", "a warning", level="warning"),
        ]
    )

    assert [message.id for message in messages] == ["labels.E002", "labels.W002"]


@pytest.mark.django_db
def test_activating_another_profile_is_picked_up(db):
    """Switching the enforced profile must not wait for the check interval."""
    first = build_profile(code="first", state="active")
    labels_compile.clear()
    assert labels_compile.active_profile().code == "first"

    first.state = "draft"
    first.save()
    build_profile(code="second", state="active")
    labels_compile.clear()

    assert labels_compile.active_profile().code == "second"
    assert LabelProfile.objects.filter(state="active").count() == 1


@pytest.mark.django_db
def test_the_boot_check_compiles_the_profile_once(profile, django_assert_max_num_queries):
    """Two checks must not compile the profile twice."""
    labels_compile.clear()

    with django_assert_max_num_queries(3):
        check_active_profile()


@pytest.mark.django_db
def test_a_profile_without_a_primary_is_an_error(profile, monkeypatch):
    """A missing primary dimension is an error."""
    without_primary = Lattice.from_spec(
        [{"code": "tier", "join": "max", "values": [{"code": "U", "rank": 0}, {"code": "DR", "rank": 1}]}]
    )
    broken = CompiledProfile(
        profile_id=profile.pk,
        code="broken",
        version=1,
        content_hash="x",
        ceiling="DR",
        lattice=without_primary,
    )
    monkeypatch.setattr("lasuite.labels.compile.active_profile", lambda **kwargs: broken)

    messages = check_active_profile()

    assert "labels.E005" in [message.id for message in messages]


@pytest.mark.django_db
def test_a_profile_that_cannot_be_compiled_is_an_error(db):
    """The check reports a broken profile as an error."""
    profile = LabelProfile.objects.create(code="broken", name="Broken")
    profile.dimensions.create(
        profile=profile,
        code="tier",
        join="max",
        is_primary=True,
        label_key="k",
        values=[{"code": "U", "rank": 0}],
    )
    profile.state = "active"
    profile.save()
    profile.dimensions.filter(code="tier").update(join="not-a-registered-operator")

    messages = check_active_profile()

    assert "labels.E006" in [message.id for message in messages]
    assert "labels.W001" not in [message.id for message in messages]
