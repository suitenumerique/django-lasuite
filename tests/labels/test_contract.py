"""Test the lattice contract suite for valid and invalid profiles."""

import math
from dataclasses import dataclass
from typing import ClassVar

import pytest

from lasuite.labels.errors import LabelError
from lasuite.labels.joins import MaxJoin
from lasuite.labels.lattice import Lattice
from lasuite.labels.testing import (
    MAX_PRODUCT,
    ContractError,
    Violation,
    assert_lattice_contract,
    check_lattice,
    dimension_samples,
    sample_labels,
    sampling_plan,
)

CHAIN_VALUES = [
    {"code": "U", "rank": 0},
    {"code": "DR", "rank": 1},
    {"code": "S", "rank": 2},
]

GOOD_SPECS = {
    "chain": [{"code": "tier", "join": "max", "is_primary": True, "values": CHAIN_VALUES}],
    "union": [{"code": "compartments", "join": "union", "values": [{"code": "a"}, {"code": "b"}]}],
    "intersection": [{"code": "releasable_to", "join": "intersection", "values": [{"code": "fr"}, {"code": "de"}]}],
    "bool": [{"code": "sf", "join": "or"}],
    "mixed": [
        {"code": "tier", "join": "max", "is_primary": True, "values": CHAIN_VALUES},
        {"code": "compartments", "join": "union", "values": [{"code": "legal"}]},
        {"code": "sf", "join": "or"},
    ],
}


@dataclass(frozen=True)
class LyingAtomsJoin(MaxJoin):
    """Test-only operator whose atom encoding does not follow the order."""

    code: ClassVar[str] = "lying-atoms"

    def atoms(self, value):
        """Return one atom for every value. This encoding is invalid."""
        return frozenset({value})


@dataclass(frozen=True)
class LyingOrderJoin(MaxJoin):
    """Test-only operator that claims everything is comparable."""

    code: ClassVar[str] = "lying-order"

    def leq(self, left, right):
        """Answer yes always, which contradicts the join."""
        return True


@dataclass(frozen=True)
class AbsorbingJoin(MaxJoin):
    """Test-only operator whose join is not idempotent."""

    code: ClassVar[str] = "absorbing"

    def join(self, left, right):
        """Jump to the top, so combining with itself moves."""
        return self.top()


def build(join_code, values=None):
    """Build a one-dimension lattice around a given operator."""
    return Lattice.from_spec(
        [
            {
                "code": "tier",
                "join": join_code,
                "is_primary": True,
                "values": values or CHAIN_VALUES,
            }
        ]
    )


@pytest.mark.parametrize("name", sorted(GOOD_SPECS))
def test_good_profiles_pass_the_contract(name):
    """Every shipped operator shape must be accepted."""
    lattice = Lattice.from_spec(GOOD_SPECS[name])

    errors = [violation for violation in check_lattice(lattice) if violation.level == "error"]

    assert errors == []
    assert_lattice_contract(lattice)


def test_contract_catches_a_broken_atom_encoding(settings):
    """The property the indexed column relies on must be verified, not assumed."""
    settings.LABELS_JOINS = {"lying-atoms": "tests.labels.test_contract.LyingAtomsJoin"}

    violations = check_lattice(build("lying-atoms"))

    assert "lattice.atoms" in {violation.code for violation in violations}
    with pytest.raises(ContractError, match="lattice.atoms"):
        assert_lattice_contract(build("lying-atoms"))


def test_contract_catches_an_order_that_contradicts_the_join(settings):
    """A profile cannot declare an order next to the operator."""
    settings.LABELS_JOINS = {"lying-order": "tests.labels.test_contract.LyingOrderJoin"}

    with pytest.raises(ContractError, match="lattice.order"):
        assert_lattice_contract(build("lying-order"))


def test_contract_catches_a_non_idempotent_join(settings):
    """Combining a label with itself does not change it."""
    settings.LABELS_JOINS = {"absorbing": "tests.labels.test_contract.AbsorbingJoin"}

    with pytest.raises(ContractError, match="lattice.idempotence"):
        assert_lattice_contract(build("absorbing"))


def test_atom_budget_is_only_a_warning():
    """A large atom set is slow, not wrong."""
    lattice = Lattice.from_spec(
        [{"code": "tags", "join": "union", "values": [{"code": str(index)} for index in range(8)]}]
    )

    violations = check_lattice(lattice, atom_budget=4)

    assert [violation.code for violation in violations] == ["lattice.atom_budget"]
    assert violations[0].level == "warning"
    assert_lattice_contract(lattice, atom_budget=4)


def test_sample_is_bounded_and_deterministic():
    """The sample size drives the cost of the boot check."""
    lattice = Lattice.from_spec([{"code": "tags", "join": "union", "values": [{"code": str(i)} for i in range(6)]}])

    first = sample_labels(lattice, limit=12)
    second = sample_labels(lattice, limit=12)

    assert len(first) <= 12
    assert first == second


def test_sample_always_contains_the_extremes():
    """A contract check without bottom and top would miss the bounds laws."""
    lattice = Lattice.from_spec([{"code": "tags", "join": "union", "values": [{"code": str(i)} for i in range(6)]}])

    labels = sample_labels(lattice, limit=8)

    assert lattice.bottom() in labels
    assert lattice.top() in labels


def test_small_profiles_are_enumerated_exhaustively():
    """Under the limit, no sampling: the whole domain is checked."""
    lattice = Lattice.from_spec(GOOD_SPECS["mixed"])

    labels = sample_labels(lattice, limit=100)

    assert len(labels) == 12


def test_contract_error_keeps_every_violation():
    """Return all violations, not only the first."""
    first = Violation("lattice.one", "first detail")
    second = Violation("lattice.two", "second detail", level="warning")

    error = ContractError([first, second])

    assert error.violations == (first, second)
    assert "first detail" in str(error)
    assert "second detail" in str(error)
    assert isinstance(error, LabelError)


def test_a_wide_profile_is_sampled_without_materialising_its_product():
    """Large profiles must not make boot checks slow."""
    lattice = Lattice.from_spec(
        [
            {"code": f"d{index}", "join": "max", "values": [{"code": f"v{rank}", "rank": rank} for rank in range(60)]}
            for index in range(4)
        ]
    )

    plan = sampling_plan(lattice, limit=24)
    labels = sample_labels(lattice, limit=24)

    assert math.prod(len(samples) for samples in plan) <= MAX_PRODUCT
    assert len(labels) <= 24
    assert lattice.bottom() in labels
    assert lattice.top() in labels


def test_sampling_keeps_both_extremes_of_a_chain():
    """Thinning must not drop what the bounds laws check."""
    lattice = Lattice.from_spec(
        [{"code": "d", "join": "max", "values": [{"code": f"v{rank}", "rank": rank} for rank in range(60)]}]
    )

    samples = dimension_samples(lattice.dimension("d"), limit=8)

    assert samples[0] == "v0"
    assert samples[-1] == "v59"
    assert len(samples) <= 8


def test_a_large_caller_limit_does_not_unbound_the_enumeration():
    """The budget is the library's, not the caller's."""
    lattice = Lattice.from_spec(
        [
            {"code": f"d{index}", "join": "max", "values": [{"code": f"v{rank}", "rank": rank} for rank in range(40)]}
            for index in range(3)
        ]
    )

    plan = sampling_plan(lattice, limit=10_000)

    assert math.prod(len(samples) for samples in plan) <= MAX_PRODUCT
