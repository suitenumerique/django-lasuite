"""Test profile models, validation, digest and the journal."""

import pytest
from django.core.exceptions import ValidationError

from lasuite.labels.errors import LabelError
from lasuite.labels.models import (
    LabelAuditAction,
    LabelAuditEvent,
    LabelDimension,
    LabelProfile,
    LabelProfileState,
)
from lasuite.labels.testing import assert_lattice_contract

TIER_VALUES = [
    {"code": "U", "rank": 0, "label_key": "igi1300.tier.u", "regime": "public"},
    {"code": "DR", "rank": 1, "label_key": "igi1300.tier.dr", "regime": "dr"},
    {"code": "S", "rank": 2, "label_key": "igi1300.tier.s", "regime": "classified"},
]


def make_profile(code="igi1300", state=LabelProfileState.DRAFT, ceiling=""):
    """Build a profile with two dimensions, tier being the primary one."""
    profile = LabelProfile.objects.create(code=code, name="IGI 1300", ceiling=ceiling)
    LabelDimension.objects.create(
        profile=profile,
        code="tier",
        join="max",
        is_primary=True,
        label_key="igi1300.tier",
        values=TIER_VALUES,
    )
    LabelDimension.objects.create(
        profile=profile,
        code="sf",
        join="or",
        label_key="igi1300.sf",
        values=[],
    )
    if state == LabelProfileState.ACTIVE:
        profile.state = state
        profile.save()
    return profile


@pytest.mark.django_db
def test_profile_builds_a_lattice_that_satisfies_the_contract():
    """The stored profile must pass the contract."""
    profile = make_profile()

    lattice = profile.to_lattice()

    assert lattice.codes == ("sf", "tier")
    assert_lattice_contract(lattice)


@pytest.mark.django_db
def test_dimension_spec_is_canonical():
    """The spec must stay stable for hashing and export."""
    profile = make_profile()

    spec = {entry["code"]: entry for entry in profile.dimensions_spec()}

    assert spec["tier"]["is_primary"] is True
    assert [value["code"] for value in spec["tier"]["values"]] == ["U", "DR", "S"]


@pytest.mark.django_db
def test_content_hash_tracks_semantic_changes_only():
    """A rename keeps meaning. A reorder changes meaning."""
    profile = make_profile()
    tier = profile.dimensions.get(code="tier")
    original = profile.content_hash

    tier.values = [dict(value, label_key=f"{value['label_key']}.renamed") for value in tier.values]
    tier.save()
    profile.refresh_from_db()
    assert profile.content_hash == original

    tier.values = [dict(value, regime="sensible") if value["code"] == "DR" else value for value in tier.values]
    tier.save()
    profile.refresh_from_db()
    assert profile.content_hash != original


@pytest.mark.django_db
def test_only_one_profile_can_be_active():
    """Only one profile can be active."""
    make_profile(code="one", state=LabelProfileState.ACTIVE)

    with pytest.raises(ValidationError, match="labels_one_active_profile"):
        make_profile(code="two", state=LabelProfileState.ACTIVE)


@pytest.mark.django_db
def test_an_active_profile_needs_a_dimension():
    """An active profile needs a dimension."""
    profile = LabelProfile(code="empty", name="Empty", state=LabelProfileState.ACTIVE)

    with pytest.raises(ValidationError, match="at least one dimension"):
        profile.full_clean()


@pytest.mark.django_db
def test_an_active_profile_needs_exactly_one_primary():
    """The profile has one primary dimension."""
    profile = make_profile()
    profile.dimensions.filter(code="sf").update(is_primary=True)
    profile.state = LabelProfileState.ACTIVE

    with pytest.raises(ValidationError, match="Exactly one dimension must be primary"):
        profile.full_clean()


@pytest.mark.django_db
def test_ceiling_must_belong_to_the_primary_dimension():
    """A ceiling must name a primary value."""
    profile = make_profile()
    profile.ceiling = "TOP"

    with pytest.raises(ValidationError, match="is not a value of the primary dimension"):
        profile.full_clean()


@pytest.mark.django_db
def test_ceiling_is_validated_against_the_chain():
    """A known value is accepted."""
    profile = make_profile()
    profile.ceiling = "DR"

    profile.full_clean()


@pytest.mark.django_db
def test_unknown_join_operator_is_refused():
    """An unknown join code is invalid."""
    profile = make_profile()
    dimension = profile.dimensions.get(code="sf")
    dimension.join = "nope"

    with pytest.raises(ValidationError, match="not a registered operator"):
        dimension.full_clean()


@pytest.mark.django_db
def test_duplicate_value_codes_are_refused():
    """Dimension value codes must be unique."""
    profile = make_profile()
    dimension = profile.dimensions.get(code="sf")
    dimension.join = "union"
    dimension.values = [{"code": "a"}, {"code": "a"}]

    with pytest.raises(ValidationError, match="must be unique"):
        dimension.full_clean()


@pytest.mark.django_db
def test_only_a_chain_can_be_primary():
    """Only a chain can be primary."""
    profile = make_profile()
    dimension = profile.dimensions.get(code="sf")
    dimension.join = "union"
    dimension.values = [{"code": "a"}]
    dimension.is_primary = True

    with pytest.raises(ValidationError, match="Only a chain can be the primary dimension"):
        dimension.full_clean()


@pytest.mark.django_db
def test_a_dimension_needs_a_translation_key():
    """A dimension needs a translation key."""
    profile = make_profile()
    dimension = profile.dimensions.get(code="sf")
    dimension.label_key = ""

    with pytest.raises(ValidationError, match="translation key"):
        dimension.full_clean()


@pytest.mark.django_db
def test_a_dimension_needs_a_domain():
    """A dimension needs at least one value."""
    profile = make_profile()
    dimension = profile.dimensions.get(code="tier")
    dimension.values = []

    with pytest.raises(ValidationError, match="at least one declared value"):
        dimension.full_clean()


@pytest.mark.django_db
def test_audit_events_are_append_only():
    """The journal rejects updates and deletes."""
    event = LabelAuditEvent.objects.create(
        action=LabelAuditAction.ASSIGN,
        model_label="core.Document",
        object_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    )

    event.action = LabelAuditAction.LOWER
    with pytest.raises(LabelError, match="append-only"):
        event.save()

    with pytest.raises(LabelError, match="append-only"):
        event.delete()


@pytest.mark.django_db
def test_audit_event_records_the_acts_of_a_profile():
    """The journal is indexed by object."""
    event = LabelAuditEvent.objects.create(
        action=LabelAuditAction.LOAD,
        model_label="labels.LabelProfile",
        object_id="igi1300",
        label={"v": 1, "values": {"tier": "DR", "sf": False}},
        profile_version=3,
    )

    assert str(event) == "load labels.LabelProfile:igi1300"
    assert LabelAuditEvent.objects.filter(model_label="labels.LabelProfile").count() == 1


@pytest.mark.django_db
def test_a_dimension_with_a_corrupt_value_cannot_describe_itself(db):
    """A corrupt row raises LabelError."""
    profile = LabelProfile.objects.create(code="corrupt", name="Corrupt")
    profile.dimensions.create(
        profile=profile,
        code="tier",
        join="max",
        is_primary=True,
        label_key="k",
        values=[{"code": "U", "rank": 0}],
    )
    LabelDimension.objects.filter(profile=profile, code="tier").update(values=[{"rank": 0}])
    dimension = LabelDimension.objects.get(profile=profile, code="tier")

    with pytest.raises(LabelError, match="without a code"):
        dimension.to_spec()
    with pytest.raises(LabelError, match="without a code"):
        dimension.declared_values()
