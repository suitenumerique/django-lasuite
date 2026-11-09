"""Test the label value object and its encoding."""

import pytest

from lasuite.labels.errors import LabelError, LabelValueError
from lasuite.labels.label import Label
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
    {"code": "compartments", "join": "union", "values": [{"code": "legal"}, {"code": "rh"}]},
]


@pytest.fixture
def lattice():
    """Return the two-dimension lattice used by the tests."""
    return Lattice.from_spec(SPEC)


def test_values_are_canonicalised(lattice):
    """A list coming from JSON must behave like a set."""
    label = Label(lattice, {"tier": "DR", "compartments": ["legal"]})

    assert label["compartments"] == frozenset({"legal"})
    assert label.values == {"tier": "DR", "compartments": frozenset({"legal"})}


def test_labels_are_equal_whatever_the_input_order(lattice):
    """Value objects compare by content."""
    one = Label(lattice, {"tier": "DR", "compartments": frozenset({"legal", "rh"})})
    other = Label(lattice, {"compartments": {"rh", "legal"}, "tier": "DR"})

    assert one == other
    assert hash(one) == hash(other)
    assert len({one, other}) == 1


def test_labels_of_different_lattices_are_not_equal(lattice):
    """Labels from different lattices must not mix."""
    other_lattice = Lattice.from_spec([{"code": "tier", "join": "max", "values": [{"code": "U", "rank": 0}]}])
    label = Label(lattice, {"tier": "U", "compartments": frozenset()})
    other = Label(other_lattice, {"tier": "U"})

    assert label != other
    with pytest.raises(LabelError, match="cannot combine labels"):
        label.join(other)


def test_bottom_and_top(lattice):
    """The extremes of the lattice are reachable as value objects."""
    for label in (
        Label(lattice, {"tier": "U", "compartments": frozenset()}),
        Label(lattice, {"tier": "DR", "compartments": frozenset({"rh"})}),
    ):
        assert Label.bottom(lattice).leq(label)
        assert label.leq(Label.top(lattice))


def test_join_and_dominance(lattice):
    """Combining is delegated to the lattice, not reimplemented."""
    left = Label(lattice, {"tier": "U", "compartments": frozenset({"legal"})})
    right = Label(lattice, {"tier": "S", "compartments": frozenset()})

    combined = left.join(right)

    assert combined.values == {"tier": "S", "compartments": frozenset({"legal"})}
    assert combined.dominates(left)
    assert combined.dominates(right)
    assert not left.dominates(combined)


def test_atoms_and_round_trip(lattice):
    """The atom form must rebuild an equal label."""
    label = Label(lattice, {"tier": "DR", "compartments": frozenset({"legal"})})

    assert label.atoms == frozenset({"tier:U", "tier:DR", "compartments:legal"})
    assert Label.from_atoms(lattice, label.atoms) == label


def test_primary_rank(lattice):
    """The rank is stored in the indexed column."""
    assert Label(lattice, {"tier": "S", "compartments": frozenset()}).primary_rank == 2


def test_encoding_is_stable_and_round_trips(lattice):
    """The stored form has a stable order."""
    label = Label(lattice, {"tier": "DR", "compartments": frozenset({"rh", "legal"})})

    encoded = label.encode()

    assert encoded == {
        "v": 1,
        "values": {"tier": "DR", "compartments": ["legal", "rh"]},
    }
    assert Label.parse(lattice, encoded) == label


def test_encoding_refuses_an_unknown_version(lattice):
    """An unknown encoding version raises an error."""
    with pytest.raises(LabelValueError, match="unsupported label encoding version"):
        Label.parse(lattice, {"v": 99, "values": {"tier": "U", "compartments": []}})


def test_encoding_refuses_missing_values(lattice):
    """A label without values is not a label."""
    with pytest.raises(LabelValueError, match="must carry its values"):
        Label.parse(lattice, {"v": 1})


def test_encoding_refuses_a_non_mapping(lattice):
    """The stored form is a mapping, and the parser says so."""
    with pytest.raises(LabelValueError, match="must be a mapping"):
        Label.parse(lattice, ["tier", "DR"])


def test_repr_is_readable(lattice):
    """Traces and admin pages show this."""
    label = Label(lattice, {"tier": "DR", "compartments": frozenset({"legal"})})

    assert repr(label) == "Label(tier=DR, compartments=['legal'])"


def test_labels_of_the_same_algebra_in_another_order_combine(lattice):
    """Dimension order is a declaration detail, not a different algebra."""
    reordered = Lattice.from_spec(list(reversed(SPEC)))
    one = Label(lattice, {"tier": "DR", "compartments": frozenset({"legal"})})
    other = Label(reordered, {"tier": "S", "compartments": frozenset()})

    combined = one.join(other)

    assert combined.values == {"tier": "S", "compartments": frozenset({"legal"})}


def test_labels_of_lattices_with_different_values_do_not_combine(lattice):
    """Same axes and different values are different lattices."""
    other_lattice = Lattice.from_spec(
        [
            {
                "code": "tier",
                "join": "max",
                "is_primary": True,
                "values": [{"code": "U", "rank": 0}, {"code": "DR", "rank": 1}, {"code": "S", "rank": 2}],
            },
            {"code": "compartments", "join": "union", "values": [{"code": "other"}]},
        ]
    )
    one = Label(lattice, {"tier": "DR", "compartments": frozenset()})
    other = Label(other_lattice, {"tier": "DR", "compartments": frozenset()})

    assert one != other
    with pytest.raises(LabelError, match="cannot combine labels"):
        one.join(other)
