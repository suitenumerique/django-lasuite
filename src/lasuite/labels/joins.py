"""
How values of one label dimension combine.

A dimension is one axis of a classification: a ranked chain such as a tier, a
family of subsets such as compartments, or a boolean flag. Each dimension picks
one join operator, which says how two values combine. The join returns the least
restrictive value that covers both inputs.

In plain terms, the join must behave consistently:

- commutative: the order of the two values does not matter;
- associative: grouping three values does not matter;
- idempotent: combining a value with itself changes nothing.

Those three properties make the result independent of how labels are reached.
They also define the order used everywhere else in the module: one value is at
most as restrictive as another when joining them does not change the second.

For readers who know the terms: a dimension is a join semilattice, the join is
a least upper bound, and the induced order is restrictiveness.

Every operator also encodes a value as a set of atoms, with two properties::

    left <: right        <=>  atoms(left) <= atoms(right)
    atoms(join(l, r))    ==  atoms(l) | atoms(r)

The first property turns "at most as restrictive" into "contains the other's
atoms". The second is the homomorphism part: the atoms of a combined value are
exactly the union of the atoms of its inputs. This lets the product lattice be
stored as one atom set and compared with one indexed column.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, runtime_checkable

from django.conf import settings
from django.utils.module_loading import import_string

from .errors import JoinError, LabelValueError

#: Restricted, most to least useful for the code that consumes it.
CHAIN = "chain"
SUBSET = "subset"
BOOL = "bool"


@dataclass(frozen=True)
class Value:
    """A declared member of a dimension domain."""

    code: str
    rank: int | None = None

    def __post_init__(self):
        """Reject declarations that no join operator can order."""
        if not self.code:
            raise JoinError("a dimension value must have a non-empty code")
        if self.rank is None:
            return
        if isinstance(self.rank, bool) or not isinstance(self.rank, int):
            # A rank read from JSON can be a string; comparing it later raises a
            # TypeError from the middle of a sort instead of naming the field.
            raise JoinError(f"value {self.code!r} has a non-integer rank {self.rank!r}")
        if self.rank < 0:
            raise JoinError(f"value {self.code!r} has a negative rank")


@runtime_checkable
class Join(Protocol):
    """Combine two values of one dimension and describe the induced order."""

    code: ClassVar[str]
    domain: ClassVar[str]

    def join(self, left: Any, right: Any) -> Any:
        """Return the least restrictive value covering both arguments."""
        ...

    def leq(self, left: Any, right: Any) -> bool:
        """Tell whether ``left`` is at most as restrictive as ``right``."""
        ...

    def bottom(self) -> Any:
        """Return the value that restricts nothing."""
        ...

    def top(self) -> Any:
        """Return the value that restricts everything."""
        ...

    def atoms(self, value: Any) -> frozenset[str]:
        """Encode a value as the set of atoms it requires."""
        ...

    def from_atoms(self, atoms: Iterable[str]) -> Any:
        """Decode an atom set back to a value, rejecting invalid sets."""
        ...

    def validate(self, value: Any) -> None:
        """Raise if the value does not belong to the domain."""
        ...


@dataclass(frozen=True)
class MaxJoin:
    """Total order of ranked values; combining keeps the highest rank."""

    code: ClassVar[str] = "max"
    domain: ClassVar[str] = CHAIN

    values: tuple[Value, ...]

    def __post_init__(self):
        """Require a contiguous, unique ranking."""
        if not self.values:
            raise JoinError("a max dimension needs at least one value")
        ranks = sorted(value.rank for value in self.values)
        if ranks != list(range(len(self.values))):
            raise JoinError(f"a {self.code} dimension needs contiguous ranks starting at 0, got {ranks}")

    def _by_code(self) -> dict[str, int]:
        return {value.code: value.rank for value in self.values}

    def _by_rank(self) -> dict[int, str]:
        return {value.rank: value.code for value in self.values}

    def validate(self, value):
        """Check that the code was declared."""
        if not isinstance(value, str) or value not in self._by_code():
            raise LabelValueError(f"{value!r} is not a value of this dimension")

    def join(self, left, right):
        """Keep the value with the highest rank."""
        self.validate(left)
        self.validate(right)
        ranks = self._by_code()
        return left if ranks[left] >= ranks[right] else right

    def leq(self, left, right):
        """Compare restrictiveness: a lower rank restricts less."""
        self.validate(left)
        self.validate(right)
        ranks = self._by_code()
        return ranks[left] <= ranks[right]

    def bottom(self):
        """Return the lowest ranked value."""
        return self._by_rank()[0]

    def top(self):
        """Return the highest ranked value."""
        return self._by_rank()[len(self.values) - 1]

    def atoms(self, value):
        """Return every value at most as restrictive as ``value``."""
        self.validate(value)
        ranks = self._by_code()
        limit = ranks[value]
        return frozenset(value.code for value in self.values if value.rank <= limit)

    def from_atoms(self, atoms):
        """Rebuild a value from a prefix of the chain."""
        atoms = frozenset(atoms)
        by_rank = self._by_rank()
        matching = [
            by_rank[value.rank]
            for value in self.values
            if frozenset(atom.code for atom in self.values if atom.rank <= value.rank) == atoms
        ]
        if len(matching) != 1:
            raise LabelValueError(f"{sorted(atoms)} is not a prefix of this chain")
        return matching[0]


@dataclass(frozen=True)
class UnionJoin:
    """Subsets of a universe; combining keeps every member of both."""

    code: ClassVar[str] = "union"
    domain: ClassVar[str] = SUBSET

    values: tuple[Value, ...]

    def __post_init__(self):
        """Require a non-empty universe of unique codes."""
        codes = [value.code for value in self.values]
        if len(set(codes)) != len(codes):
            raise JoinError("a subset universe cannot declare the same code twice")

    def _universe(self) -> frozenset[str]:
        return frozenset(value.code for value in self.values)

    def validate(self, value):
        """Check that the value is a subset of the universe."""
        if not isinstance(value, (frozenset, set)):
            raise LabelValueError(f"{value!r} is not a set")
        unknown = frozenset(value) - self._universe()
        if unknown:
            raise LabelValueError(f"{sorted(unknown)} are not members of this universe")

    def join(self, left, right):
        """Union the two sets."""
        self.validate(left)
        self.validate(right)
        return frozenset(left) | frozenset(right)

    def leq(self, left, right):
        """Compare restrictiveness: a smaller set restricts less."""
        self.validate(left)
        self.validate(right)
        return frozenset(left) <= frozenset(right)

    def bottom(self):
        """Return the empty set."""
        return frozenset()

    def top(self):
        """Return the whole universe."""
        return self._universe()

    def atoms(self, value):
        """Return each required member as its own atom."""
        self.validate(value)
        return frozenset(value)

    def from_atoms(self, atoms):
        """Rebuild the set; atoms and members are the same thing."""
        value = frozenset(atoms)
        self.validate(value)
        return value


@dataclass(frozen=True)
class IntersectionJoin:
    """Subsets of a universe; combining keeps only what both may reach."""

    code: ClassVar[str] = "intersection"
    domain: ClassVar[str] = SUBSET

    values: tuple[Value, ...]

    def __post_init__(self):
        """Require a non-empty universe of unique codes."""
        codes = [value.code for value in self.values]
        if len(set(codes)) != len(codes):
            raise JoinError("a subset universe cannot declare the same code twice")

    def _universe(self) -> frozenset[str]:
        return frozenset(value.code for value in self.values)

    def validate(self, value):
        """Check that the value is a subset of the universe."""
        if not isinstance(value, (frozenset, set)):
            raise LabelValueError(f"{value!r} is not a set")
        unknown = frozenset(value) - self._universe()
        if unknown:
            raise LabelValueError(f"{sorted(unknown)} are not members of this universe")

    def join(self, left, right):
        """Intersect the two sets."""
        self.validate(left)
        self.validate(right)
        return frozenset(left) & frozenset(right)

    def leq(self, left, right):
        """Compare restrictiveness: a larger set restricts less, so ``left`` contains ``right``."""
        self.validate(left)
        self.validate(right)
        return frozenset(left) >= frozenset(right)

    def bottom(self):
        """Return the whole universe: nothing is out of reach."""
        return self._universe()

    def top(self):
        """Return the empty set: nothing is reachable."""
        return frozenset()

    def atoms(self, value):
        """Encode the complement so that containment follows restrictiveness."""
        self.validate(value)
        return self._universe() - frozenset(value)

    def from_atoms(self, atoms):
        """Decode the complement back to a value."""
        atoms = frozenset(atoms)
        if not atoms <= self._universe():
            raise LabelValueError(f"{sorted(atoms - self._universe())} are not members of this universe")
        return self._universe() - atoms


@dataclass(frozen=True)
class OrJoin:
    """Booleans; combining keeps the value that restricts the most."""

    code: ClassVar[str] = "or"
    domain: ClassVar[str] = BOOL

    values: tuple[Value, ...] = ()

    def validate(self, value):
        """Check that the value is a boolean."""
        if not isinstance(value, bool):
            raise LabelValueError(f"{value!r} is not a boolean")

    def join(self, left, right):
        """Return the disjunction."""
        self.validate(left)
        self.validate(right)
        return left or right

    def leq(self, left, right):
        """Compare restrictiveness: ``True`` restricts more than ``False``."""
        self.validate(left)
        self.validate(right)
        return (not left) or bool(right)

    def bottom(self):
        """Return ``False``."""
        return False

    def top(self):
        """Return ``True``."""
        return True

    def atoms(self, value):
        """Return the atom of a ``True`` flag, or nothing for ``False``."""
        self.validate(value)
        return frozenset({self.code}) if value else frozenset()

    def from_atoms(self, atoms):
        """Decode the flag from the presence of its atom."""
        atoms = frozenset(atoms)
        if not atoms <= {self.code}:
            raise LabelValueError(f"{sorted(atoms)} is not a valid boolean encoding")
        return self.code in atoms


#: Operators shipped with the package. Instances may add their own through the
#: ``LABELS_JOINS`` setting. The registry merges it into this mapping.
JOINS: dict[str, type[Join]] = {
    MaxJoin.code: MaxJoin,
    UnionJoin.code: UnionJoin,
    IntersectionJoin.code: IntersectionJoin,
    OrJoin.code: OrJoin,
}


def join_registry() -> dict[str, type[Join]]:
    """Return the available operators, including the instance's own."""
    registry = dict(JOINS)
    for code, path in (getattr(settings, "LABELS_JOINS", None) or {}).items():
        try:
            registry[code] = import_string(path)
        except ImportError as err:
            raise JoinError(f"could not import join operator {code!r} from {path!r}") from err
    return registry


def join_for(code: str, values: Sequence[Value] = ()) -> Join:
    """Instantiate the operator declared for a dimension."""
    try:
        operator = join_registry()[code]
    except KeyError as err:
        available = ", ".join(sorted(join_registry()))
        raise JoinError(f"unknown join operator {code!r}, available: {available}") from err

    if operator.code != code:
        # The code of the operator ends up in every label signature and in the
        # profile digest, so a class registered under another name can make
        # two different algebras look identical.
        raise JoinError(f"join operator {code!r} is implemented by a class declaring {operator.code!r}")
    if operator.domain == BOOL:
        return operator()
    return operator(tuple(values))
