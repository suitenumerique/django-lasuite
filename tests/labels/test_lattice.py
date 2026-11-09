"""Test product lattice laws, atom encoding and validation."""

import pytest

from lasuite.labels.errors import LabelError, LabelValueError
from lasuite.labels.lattice import Lattice

SPEC = [
    {
        "code": "tier",
        "join": "max",
        "is_primary": True,
        "values": [
            {"code": "U", "rank": 0},
            {"code": "DR", "rank": 1},
            {"code": "S", "rank": 2},
        ],
    },
    {
        "code": "compartments",
        "join": "union",
        "values": [{"code": "legal"}, {"code": "rh"}],
    },
    {"code": "sf", "join": "or"},
]


@pytest.fixture
def lattice():
    """Return the three-dimension lattice used throughout the tests."""
    return Lattice.from_spec(SPEC)


def samples(lattice):
    """Return every label of the test lattice."""
    return [
        {"tier": tier, "compartments": compartments, "sf": flag}
        for tier in ("U", "DR", "S")
        for compartments in (
            frozenset(),
            frozenset({"legal"}),
            frozenset({"rh"}),
            frozenset({"legal", "rh"}),
        )
        for flag in (False, True)
    ]


def test_from_spec_builds_every_dimension(lattice):
    """The declarative form must be enough to build the algebra."""
    assert lattice.codes == ("tier", "compartments", "sf")
    assert lattice.primary is not None
    assert lattice.primary.code == "tier"
    assert [dimension.join.domain for dimension in lattice.dimensions] == [
        "chain",
        "subset",
        "bool",
    ]


def test_cardinality_and_atom_budget(lattice):
    """Both estimates support the admin and the checks."""
    assert lattice.cardinality() == 3 * 4 * 2
    assert lattice.atoms_per_label() == 3 + 2 + 1


def test_product_join_is_commutative(lattice):
    """Combination must not depend on the order of the arguments."""
    every = samples(lattice)
    for left in every:
        for right in every:
            assert lattice.join(left, right) == lattice.join(right, left)


def test_product_join_is_associative(lattice):
    """Combination must not depend on the grouping."""
    every = samples(lattice)
    for first in every:
        for second in every:
            for third in every:
                assert lattice.join(lattice.join(first, second), third) == lattice.join(
                    first, lattice.join(second, third)
                )


def test_product_join_is_idempotent(lattice):
    """Combining a label with itself changes nothing."""
    for label in samples(lattice):
        assert lattice.join(label, label) == label


def test_order_is_derived_from_the_join(lattice):
    """The join defines the order."""
    every = samples(lattice)
    for left in every:
        for right in every:
            assert lattice.leq(left, right) == (lattice.join(left, right) == right)


def test_atoms_are_a_join_homomorphism(lattice):
    """The union of atoms must be the atoms of the join, for the whole product."""
    every = samples(lattice)
    for left in every:
        for right in every:
            assert lattice.atoms(lattice.join(left, right)) == (lattice.atoms(left) | lattice.atoms(right))


def test_atoms_mirror_the_order(lattice):
    """Containment of atoms must follow restrictiveness across dimensions."""
    every = samples(lattice)
    for left in every:
        for right in every:
            assert lattice.leq(left, right) == (lattice.atoms(left) <= lattice.atoms(right))


def test_atoms_round_trip(lattice):
    """A stored atom set must decode back to the same label."""
    for label in samples(lattice):
        assert lattice.from_atoms(lattice.atoms(label)) == label


def test_atoms_are_namespaced_per_dimension():
    """Two dimensions may declare the same value code without colliding."""
    lattice = Lattice.from_spec(
        [
            {"code": "a", "join": "union", "values": [{"code": "x"}]},
            {"code": "b", "join": "union", "values": [{"code": "x"}]},
        ]
    )
    label = {"a": frozenset({"x"}), "b": frozenset({"x"})}

    assert lattice.atoms(label) == frozenset({"a:x", "b:x"})
    assert lattice.from_atoms({"a:x"}) == {"a": frozenset({"x"}), "b": frozenset()}


def test_bottom_and_top(lattice):
    """Every label sits between the two extremes."""
    for label in samples(lattice):
        assert lattice.leq(lattice.bottom(), label)
        assert lattice.leq(label, lattice.top())
        assert lattice.join(lattice.top(), label) == lattice.top()


def test_unknown_dimension_is_rejected(lattice):
    """A label may only mention declared dimensions."""
    with pytest.raises(LabelValueError, match="unknown dimensions"):
        lattice.validate({"tier": "U", "compartments": frozenset(), "sf": False, "x": 1})


def test_missing_dimension_is_rejected(lattice):
    """A label must be total, so adding a dimension cannot be silently ignored."""
    with pytest.raises(LabelValueError, match="missing dimensions"):
        lattice.validate({"tier": "U"})


def test_invalid_value_is_rejected(lattice):
    """Validation delegates to the dimension, not to a guess."""
    with pytest.raises(LabelValueError):
        lattice.validate({"tier": "TOP", "compartments": frozenset(), "sf": False})


def test_foreign_atom_is_rejected(lattice):
    """An atom from another profile must not be silently dropped."""
    with pytest.raises(LabelValueError, match="does not belong"):
        lattice.from_atoms({"tier:U", "unknown:value"})


def test_dimension_codes_cannot_contain_the_separator():
    """The atom namespace would otherwise become ambiguous."""
    with pytest.raises(LabelError, match="cannot contain"):
        Lattice.from_spec([{"code": "a:b", "join": "or"}])


def test_value_codes_cannot_contain_the_separator():
    """Duplicate value codes are invalid."""
    with pytest.raises(LabelError, match="cannot contain"):
        Lattice.from_spec([{"code": "a", "join": "union", "values": [{"code": "x:y"}]}])


def test_duplicate_dimension_codes_are_rejected():
    """Two dimensions with one code would shadow each other."""
    with pytest.raises(LabelError, match="duplicate dimension"):
        Lattice.from_spec([{"code": "a", "join": "or"}, {"code": "a", "join": "or"}])


def test_only_one_dimension_can_be_primary():
    """A profile must have exactly one primary dimension."""
    with pytest.raises(LabelError, match="only one dimension"):
        Lattice.from_spec(
            [
                {"code": "a", "join": "or", "is_primary": True},
                {"code": "b", "join": "or", "is_primary": True},
            ]
        )


def test_an_empty_lattice_is_rejected():
    """A profile with no axis cannot express anything."""
    with pytest.raises(LabelError, match="at least one dimension"):
        Lattice(dimensions=())


def test_describe_is_serialisable(lattice):
    """The admin and the checks read this summary."""
    described = {entry["code"]: entry for entry in lattice.describe()}

    assert described["tier"] == {
        "code": "tier",
        "join": "max",
        "domain": "chain",
        "size": 3,
        "is_primary": True,
    }
    assert described["sf"]["size"] == 2


def test_the_signature_ignores_declaration_order():
    """Two profiles that declare the same axes in another order are one algebra."""
    one = Lattice.from_spec([{"code": "a", "join": "or"}, {"code": "b", "join": "union", "values": [{"code": "x"}]}])
    other = Lattice.from_spec([{"code": "b", "join": "union", "values": [{"code": "x"}]}, {"code": "a", "join": "or"}])

    assert one.signature == other.signature


def test_the_signature_includes_the_declared_values():
    """Same operators, different universes: not the same algebra."""
    one = Lattice.from_spec([{"code": "a", "join": "union", "values": [{"code": "x"}]}])
    other = Lattice.from_spec([{"code": "a", "join": "union", "values": [{"code": "y"}]}])

    assert one.signature != other.signature


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"code": "x"}, "as a list"),
        (["x"], "without a code"),
        ([{"rank": 0}], "without a code"),
    ],
)
def test_a_malformed_domain_is_a_label_error(values, message):
    """A hand-edited file must name the problem, not raise from a comprehension."""
    with pytest.raises(LabelError, match=message):
        Lattice.from_spec([{"code": "a", "join": "union", "values": values}])


def test_a_spec_that_is_not_a_list_of_mappings_is_a_label_error():
    """A hand-built spec must name the problem, not raise from a loop."""
    with pytest.raises(LabelError, match="list of dimensions"):
        Lattice.from_spec({"code": "a", "join": "or"})
    with pytest.raises(LabelError, match="list of dimensions"):
        Lattice.from_spec(None)
    with pytest.raises(LabelError, match="must be a mapping"):
        Lattice.from_spec(["a"])
