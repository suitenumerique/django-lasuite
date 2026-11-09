"""Fixtures for labels tests."""

import pytest

from lasuite.labels import compile as labels_compile
from lasuite.labels.models import LabelDimension, LabelProfile, LabelProfileState

TIER_VALUES = [
    {"code": "U", "rank": 0, "label_key": "igi1300.tier.u", "regime": "public"},
    {"code": "DR", "rank": 1, "label_key": "igi1300.tier.dr", "regime": "dr"},
    {"code": "S", "rank": 2, "label_key": "igi1300.tier.s", "regime": "classified"},
]

COMPARTMENT_VALUES = [{"code": "legal"}, {"code": "rh"}]


def build_profile(code="igi1300", state=LabelProfileState.DRAFT, ceiling=""):
    """Create a profile with a chain, a subset and a boolean dimension."""
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
        code="compartments",
        join="union",
        label_key="igi1300.compartments",
        values=COMPARTMENT_VALUES,
    )
    LabelDimension.objects.create(profile=profile, code="sf", join="or", label_key="igi1300.sf", values=[])
    if state == LabelProfileState.ACTIVE:
        profile.state = state
        profile.save()
    return profile


@pytest.fixture(autouse=True)
def reset_compiled_profile():
    """Reset the compiled profile before and after each test."""
    labels_compile.clear()
    yield
    labels_compile.clear()


@pytest.fixture
def profile(db):
    """Return an active profile."""
    return build_profile(state=LabelProfileState.ACTIVE, ceiling="DR")
