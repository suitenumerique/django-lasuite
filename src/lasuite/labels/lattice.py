"""
A label profile as a small, composable classification system.

In mathematical terms, a profile is a product lattice: each dimension is a
join semilattice, the join is a least upper bound, the order is derived from
the join, and the atom encoding is a join homomorphism.

In plain terms:

- A label is one answer per dimension, for example a tier, a set of
  compartments and a releasability set.
- Each dimension defines how two answers combine. The result is the least
  restrictive answer that covers both.
- The order follows from that rule: label A is at most as restrictive as B
  when A can be combined into B without changing B.
- A profile combines independent dimensions. A whole label is combined one
  dimension at a time.
- A label is stored twice: as readable values, and as a flat set of atoms.
  An atom is a stable name for one requirement, such as ``tier:DR``. The
  atoms of a combined label are exactly the union of the atoms of its parts.
  A join homomorphism means that the encoding preserves the combination rule.
- Because of that property, "A is at most as restrictive as B" becomes
  "A's atoms are contained in B's atoms". A single indexed text column can
  answer that question without a join per dimension.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .errors import LabelError, LabelValueError
from .joins import BOOL, SUBSET, Value, join_for

#: Separates the dimension code from the value code in an atom.
SEPARATOR = ":"

Values = Mapping[str, Any]


@dataclass(frozen=True)
class Dimension:
    """One axis of a profile, bound to its join operator."""

    code: str
    join: Any = field(repr=False)
    is_primary: bool = False

    def __post_init__(self):
        """Reject codes that make the atom namespace ambiguous."""
        if not self.code:
            raise LabelError("a dimension must have a non-empty code")
        if SEPARATOR in self.code:
            raise LabelError(f"dimension code {self.code!r} cannot contain {SEPARATOR!r}")
        for value in getattr(self.join, "values", ()):
            if SEPARATOR in value.code:
                raise LabelError(f"value code {value.code!r} cannot contain {SEPARATOR!r}")

    def validate(self, value):
        """Check the value against the dimension's domain."""
        self.join.validate(value)

    @property
    def size(self) -> int:
        """Return the number of possible values of this dimension."""
        if self.join.domain == BOOL:
            return 2
        if self.join.domain == SUBSET:
            return 2 ** len(self.join.values)
        return len(self.join.values)

    @property
    def atoms_per_value(self) -> int:
        """Return the largest number of atoms a value of this dimension needs."""
        if self.join.domain == BOOL:
            return 1
        return len(self.join.values)


@dataclass(frozen=True)
class Lattice:
    """The product of a profile's dimensions."""

    dimensions: tuple[Dimension, ...]

    def __post_init__(self):
        """Require at least one dimension and a usable primary."""
        if not self.dimensions:
            raise LabelError("a lattice needs at least one dimension")
        codes = [dimension.code for dimension in self.dimensions]
        if len(set(codes)) != len(codes):
            raise LabelError(f"duplicate dimension codes: {sorted(codes)}")
        primaries = [dimension.code for dimension in self.dimensions if dimension.is_primary]
        if len(primaries) > 1:
            raise LabelError(f"only one dimension can be primary, got {sorted(primaries)}")

    @classmethod
    def from_spec(cls, spec: Sequence[Mapping[str, Any]]) -> Lattice:
        """Build a lattice from the declarative form stored in a profile."""
        if not isinstance(spec, (list, tuple)):
            raise LabelError(f"a lattice needs a list of dimensions, got {type(spec).__name__}")
        dimensions = []
        for entry in spec:
            if not isinstance(entry, Mapping):
                raise LabelError(f"a dimension must be a mapping, got {type(entry).__name__}")
            try:
                code = entry["code"]
                join_code = entry["join"]
            except KeyError as err:
                raise LabelError(f"a dimension needs a code and a join, got {entry!r}") from err
            raw_values = entry.get("values", ())
            if not isinstance(raw_values, (list, tuple)):
                raise LabelError(
                    f"dimension {code!r} must declare its values as a list, got {type(raw_values).__name__}"
                )
            declared = []
            for value in raw_values:
                if not isinstance(value, Mapping) or "code" not in value:
                    raise LabelError(f"dimension {code!r} has a value without a code: {value!r}")
                declared.append(Value(code=value["code"], rank=value.get("rank")))
            values = tuple(declared)
            dimensions.append(
                Dimension(
                    code=code,
                    join=join_for(join_code, values),
                    is_primary=bool(entry.get("is_primary", False)),
                )
            )
        return cls(dimensions=tuple(dimensions))

    @property
    def codes(self) -> tuple[str, ...]:
        """Return the dimension codes in declaration order."""
        return tuple(dimension.code for dimension in self.dimensions)

    @property
    def signature(self) -> tuple:
        """
        Identify the algebra: codes, joins and every declared value.

        The tuple is order-insensitive, because two profiles that declare the
        same axes in a different order describe the same lattice, and it
        includes the declared values, because two lattices that agree on the
        operators but not on the universes are not the same algebra at all.
        """
        return tuple(
            sorted(
                (
                    dimension.code,
                    dimension.join.code,
                    dimension.join.domain,
                    tuple(sorted(value.code for value in getattr(dimension.join, "values", ()))),
                )
                for dimension in self.dimensions
            )
        )

    @property
    def primary(self) -> Dimension | None:
        """Return the dimension meant to carry the indexed rank, if declared."""
        return next((dimension for dimension in self.dimensions if dimension.is_primary), None)

    def dimension(self, code: str) -> Dimension:
        """Return a dimension by code."""
        for dimension in self.dimensions:
            if dimension.code == code:
                return dimension
        raise LabelError(f"unknown dimension {code!r}, expected one of {list(self.codes)}")

    def validate(self, values: Values) -> None:
        """Check that a full set of values belongs to the lattice."""
        unknown = set(values) - set(self.codes)
        if unknown:
            raise LabelValueError(f"unknown dimensions: {sorted(unknown)}")
        missing = set(self.codes) - set(values)
        if missing:
            raise LabelValueError(f"missing dimensions: {sorted(missing)}")
        for dimension in self.dimensions:
            dimension.validate(values[dimension.code])

    def bottom(self) -> dict[str, Any]:
        """Return the value that restricts nothing on any dimension."""
        return {dimension.code: dimension.join.bottom() for dimension in self.dimensions}

    def top(self) -> dict[str, Any]:
        """Return the value that restricts everything on every dimension."""
        return {dimension.code: dimension.join.top() for dimension in self.dimensions}

    def join(self, left: Values, right: Values) -> dict[str, Any]:
        """Combine two labels dimension by dimension."""
        self.validate(left)
        self.validate(right)
        return {
            dimension.code: dimension.join.join(left[dimension.code], right[dimension.code])
            for dimension in self.dimensions
        }

    def leq(self, left: Values, right: Values) -> bool:
        """Tell whether ``left`` is at most as restrictive as ``right``."""
        self.validate(left)
        self.validate(right)
        return all(dimension.join.leq(left[dimension.code], right[dimension.code]) for dimension in self.dimensions)

    def atoms(self, values: Values) -> frozenset[str]:
        """Encode a label as the set of namespaced atoms it requires."""
        self.validate(values)
        return frozenset(
            f"{dimension.code}{SEPARATOR}{atom}"
            for dimension in self.dimensions
            for atom in dimension.join.atoms(values[dimension.code])
        )

    def from_atoms(self, atoms: Iterable[str]) -> dict[str, Any]:
        """Decode a set of namespaced atoms back to a label."""
        per_dimension: dict[str, set[str]] = {code: set() for code in self.codes}
        for atom in atoms:
            code, _, rest = atom.partition(SEPARATOR)
            if not rest or code not in per_dimension:
                raise LabelValueError(f"atom {atom!r} does not belong to this lattice")
            per_dimension[code].add(rest)
        return {
            dimension.code: dimension.join.from_atoms(per_dimension[dimension.code]) for dimension in self.dimensions
        }

    def cardinality(self) -> int:
        """Return the number of distinct labels this lattice can express."""
        return math.prod(dimension.size for dimension in self.dimensions)

    def atoms_per_label(self) -> int:
        """Return the largest atom set a label of this lattice can need."""
        return sum(dimension.atoms_per_value for dimension in self.dimensions)

    def describe(self) -> list[dict[str, Any]]:
        """Return a serialisable summary, used by the admin and the checks."""
        return [
            {
                "code": dimension.code,
                "join": dimension.join.code,
                "domain": dimension.join.domain,
                "size": dimension.size,
                "is_primary": dimension.is_primary,
            }
            for dimension in self.dimensions
        ]
