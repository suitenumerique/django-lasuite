"""Test active profile compilation and cache refresh."""

import pytest

from lasuite.labels import compile as labels_compile
from lasuite.labels.compile import active_profile, compile_profile
from lasuite.labels.errors import LabelError
from lasuite.labels.models import LabelDimension

from .conftest import build_profile


class BrokenCache:
    """Cache backend that raises on every call."""

    def get(self, key):
        """Raise ConnectionError."""
        raise ConnectionError("cache is down")

    def set(self, key, value, timeout=None):
        """Raise ConnectionError."""
        raise ConnectionError("cache is down")

    def delete(self, key):
        """Raise ConnectionError."""
        raise ConnectionError("cache is down")


@pytest.mark.django_db
def test_compiled_profile_carries_what_a_request_needs(profile):
    """The compiled profile carries the fields a request needs."""
    compiled = active_profile()

    assert compiled.code == "igi1300"
    assert compiled.ceiling == "DR"
    assert compiled.version == 1
    assert compiled.content_hash == profile.content_hash
    assert compiled.lattice.codes == ("compartments", "sf", "tier")
    assert compiled.lattice.primary.code == "tier"


@pytest.mark.django_db
def test_the_second_call_does_not_touch_the_database(profile, django_assert_num_queries):
    """The request path must not query the lattice."""
    active_profile()

    with django_assert_num_queries(0):
        again = active_profile()

    assert again.content_hash == profile.content_hash


@pytest.mark.django_db
def test_a_published_change_is_picked_up(profile):
    """A published profile is visible after the check interval."""
    first = active_profile()

    dimension = LabelDimension.objects.get(profile=profile, code="tier")
    LabelDimension.objects.filter(pk=dimension.pk).update(
        values=[dict(value, rank=2 - value["rank"]) for value in dimension.values]
    )
    profile.refresh_content_hash()
    labels_compile.reset_check_interval()

    second = active_profile()

    assert second.content_hash != first.content_hash
    assert second.lattice.dimension("tier").join.top() == "U"


@pytest.mark.django_db
def test_force_recompiles_immediately(profile):
    """force=True reloads the profile immediately."""
    first = active_profile()
    profile.version = 7
    profile.save()

    second = active_profile(force=True)

    assert second.version == 7
    assert second.content_hash == first.content_hash


@pytest.mark.django_db
def test_a_zero_interval_rechecks_without_querying(profile, settings, django_assert_num_queries):
    """A zero TTL checks the digest on every call."""
    settings.LABELS_CACHE_TTL = 0
    active_profile()

    with django_assert_num_queries(0):
        assert active_profile().code == "igi1300"


@pytest.mark.django_db
def test_a_broken_cache_falls_back_to_the_database(profile, monkeypatch):
    """A cache outage does not stop profile reads."""
    monkeypatch.setattr(labels_compile, "cache", BrokenCache())

    compiled = active_profile()

    assert compiled.code == "igi1300"
    assert len(compiled.lattice.dimensions) == 3


@pytest.mark.django_db
def test_no_active_profile_is_a_configuration_error():
    """A missing profile raises LabelError."""
    build_profile(state="draft")

    with pytest.raises(LabelError, match="no active label profile"):
        active_profile()


@pytest.mark.django_db
def test_a_draft_can_be_compiled_for_preview(db):
    """The admin and loader compile drafts without activation."""
    draft = build_profile(state="draft")

    compiled = compile_profile(draft)

    assert compiled.lattice.primary.code == "tier"
    assert compiled.content_hash == draft.compute_content_hash()

