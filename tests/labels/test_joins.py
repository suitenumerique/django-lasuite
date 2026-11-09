"""Test join operators, atom encoding and the registry."""

from dataclasses import dataclass
from itertools import combinations
from typing import ClassVar

import pytest

from lasuite.labels.errors import JoinError, LabelValueError
from lasuite.labels.joins import (
    BOOL,
    CHAIN,
    IntersectionJoin,
    MaxJoin,
    OrJoin,
    UnionJoin,
    Value,
    join_for,
    join_registry,
)


def powerset(items):
    """Return every subset of ``items`` as frozensets."""
    return [frozenset(combination) for size in range(len(items) + 1) for combination in combinations(items, size)]


CHAIN_JOIN = MaxJoin(values=(Value("U", 0), Value("DR", 1), Value("S", 2), Value("TS", 3)))
UNION_JOIN = UnionJoin(values=(Value("a"), Value("b"), Value("c")))
INTERSECTION_JOIN = IntersectionJoin(values=(Value("a"), Value("b"), Value("c")))
OR_JOIN = OrJoin()

OPERATORS = {
    "max": (CHAIN_JOIN, ["U", "DR", "S", "TS"]),
    "union": (UNION_JOIN, powerset(["a", "b", "c"])),
    "intersection": (INTERSECTION_JOIN, powerset(["a", "b", "c"])),
    "or": (OR_JOIN, [False, True]),
}


@dataclass(frozen=True)
class NotOrJoin(OrJoin):
    """Test-only boolean operator, used to prove the registry is pluggable."""

    code: ClassVar[str] = "not-or"


@pytest.fixture(params=sorted(OPERATORS))
def operator(request):
    """Yield every shipped operator with a sample of its domain."""
    return OPERATORS[request.param]


def test_join_is_commutative(operator):
    """Order of combination must not matter."""
    join, samples = operator
    for left in samples:
        for right in samples:
            assert join.join(left, right) == join.join(right, left)


def test_join_is_associative(operator):
    """Grouping of combinations must not matter."""
    join, samples = operator
    for first in samples:
        for second in samples:
            for third in samples:
                assert join.join(join.join(first, second), third) == join.join(first, join.join(second, third))


def test_join_is_idempotent(operator):
    """Combining a value with itself does not change it."""
    join, samples = operator
    for value in samples:
        assert join.join(value, value) == value


def test_leq_matches_join(operator):
    """The join defines the order."""
    join, samples = operator
    for left in samples:
        for right in samples:
            assert join.leq(left, right) == (join.join(left, right) == right)


def test_bottom_and_top(operator):
    """Bottom restricts nothing, top restricts everything."""
    join, samples = operator
    for value in samples:
        assert join.leq(join.bottom(), value)
        assert join.leq(value, join.top())
        assert join.join(join.bottom(), value) == value
        assert join.join(value, join.top()) == join.top()


def test_atoms_are_a_join_homomorphism(operator):
    """A union of atoms must be the atoms of the join, per operator."""
    join, samples = operator
    for left in samples:
        for right in samples:
            assert join.atoms(join.join(left, right)) == join.atoms(left) | join.atoms(right)


def test_atoms_mirror_restrictiveness(operator):
    """Containment of atoms must follow the order exactly."""
    join, samples = operator
    for left in samples:
        for right in samples:
            assert join.leq(left, right) == (join.atoms(left) <= join.atoms(right))


def test_atoms_round_trip(operator):
    """Decoding the atoms of a value must give the value back."""
    join, samples = operator
    for value in samples:
        assert join.from_atoms(join.atoms(value)) == value


def test_from_atoms_rejects_foreign_atoms(operator):
    """An atom set that no value produces must be refused."""
    join, _ = operator
    with pytest.raises(LabelValueError):
        join.from_atoms({"not-an-atom"})


def test_unknown_value_is_rejected(operator):
    """Every operator validates its domain."""
    join, _ = operator
    with pytest.raises(LabelValueError):
        join.validate("nope" if join.domain == CHAIN else 1.5)


def test_max_requires_contiguous_ranks():
    """A chain with gaps has no well defined order."""
    with pytest.raises(JoinError, match="contiguous"):
        MaxJoin(values=(Value("U", 0), Value("S", 2)))


def test_max_requires_a_value():
    """An empty chain cannot be joined."""
    with pytest.raises(JoinError, match="at least one value"):
        MaxJoin(values=())


def test_max_from_atoms_rejects_a_non_prefix():
    """Half a chain is not a value."""
    with pytest.raises(LabelValueError, match="prefix"):
        CHAIN_JOIN.from_atoms({"DR", "TS"})


def test_subset_universe_rejects_duplicates():
    """Duplicate atom codes are invalid."""
    with pytest.raises(JoinError, match="twice"):
        UnionJoin(values=(Value("a"), Value("a")))


def test_subset_rejects_unknown_members():
    """A subset may not invent members."""
    with pytest.raises(LabelValueError, match="not members"):
        UNION_JOIN.validate(frozenset({"a", "z"}))


def test_bool_only_accepts_booleans():
    """An int is not a boolean, even though ``1 == True``."""
    with pytest.raises(LabelValueError):
        OR_JOIN.validate(1)


def test_unknown_operator_is_reported_with_the_available_ones():
    """A typo in the profile must name the valid operators."""
    with pytest.raises(JoinError, match="unknown join operator 'nope'"):
        join_for("nope")


def test_registry_can_be_extended_per_instance(settings):
    """An instance can add its own operator without a fork."""
    settings.LABELS_JOINS = {"not-or": "tests.labels.test_joins.NotOrJoin"}

    operator = join_for("not-or")

    assert isinstance(operator, NotOrJoin)
    assert operator.domain == BOOL
    assert operator.join(False, False) is False


def test_registry_reports_an_unimportable_operator(settings):
    """A broken setting raises an error."""
    settings.LABELS_JOINS = {"bogus": "tests.labels.test_joins.DoesNotExist"}

    with pytest.raises(JoinError, match="could not import join operator 'bogus'"):
        join_registry()


def test_a_rank_read_from_json_must_be_an_integer():
    """A string rank raises an error with the field name."""
    with pytest.raises(JoinError, match="non-integer rank"):
        Value(code="U", rank="1")


def test_a_boolean_is_not_a_rank():
    """True and 1 must not compare as equal."""
    with pytest.raises(JoinError, match="non-integer rank"):
        Value(code="U", rank=True)


def test_an_operator_must_answer_to_the_code_it_is_registered_under(settings):
    """A mismatch must not share a signature."""
    settings.LABELS_JOINS = {"alias": "tests.labels.test_joins.NotOrJoin"}

    with pytest.raises(JoinError, match="declaring 'not-or'"):
        join_for("alias")
