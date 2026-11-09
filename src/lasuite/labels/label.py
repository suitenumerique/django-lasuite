"""
Label value object.

A label is the ordered part. It is hashable and comparable. It joins through
the profile lattice.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import LabelError, LabelValueError
from .joins import SUBSET
from .lattice import Lattice

#: Bumped whenever the encoded form changes in an incompatible way.
ENCODING_VERSION = 1


class Label:
    """
    A label in a profile lattice. It is immutable and hashable.

    The constructor canonicalises sets and dimension order. Labels with the
    same data are equal and have the same hash.
    """

    __slots__ = ("_items", "_lattice", "_signature")

    def __init__(self, lattice: Lattice, values: Mapping[str, Any]):
        """Validate the values and store them in dimension order."""
        coerced = dict(values)
        for dimension in lattice.dimensions:
            raw = coerced.get(dimension.code)
            if dimension.join.domain == SUBSET and isinstance(raw, (list, tuple, set)):
                coerced[dimension.code] = frozenset(raw)
        lattice.validate(coerced)
        self._lattice = lattice
        self._items = tuple((dimension.code, coerced[dimension.code]) for dimension in lattice.dimensions)
        self._signature = lattice.signature

    @classmethod
    def bottom(cls, lattice: Lattice) -> Label:
        """Return the label that restricts nothing."""
        return cls(lattice, lattice.bottom())

    @classmethod
    def top(cls, lattice: Lattice) -> Label:
        """Return the label that restricts everything."""
        return cls(lattice, lattice.top())

    @classmethod
    def from_atoms(cls, lattice: Lattice, atoms) -> Label:
        """Build a label from an atom set."""
        return cls(lattice, lattice.from_atoms(atoms))

    @classmethod
    def parse(cls, lattice: Lattice, data: Mapping[str, Any]) -> Label:
        """Read the stored label form. Reject unknown encoding versions."""
        if not isinstance(data, Mapping):
            raise LabelValueError(f"a label must be a mapping, got {type(data).__name__}")
        version = data.get("v")
        if version != ENCODING_VERSION:
            raise LabelValueError(f"unsupported label encoding version {version!r}")
        values = data.get("values")
        if not isinstance(values, Mapping):
            raise LabelValueError("a label must carry its values")
        return cls(lattice, values)

    @property
    def lattice(self) -> Lattice:
        """Return the lattice for this label."""
        return self._lattice

    @property
    def values(self) -> dict[str, Any]:
        """Return the dimension values as a dictionary."""
        return dict(self._items)

    @property
    def signature(self) -> tuple:
        """Return the lattice signature."""
        return self._signature

    @property
    def atoms(self) -> frozenset[str]:
        """Return the atoms for this label."""
        return self._lattice.atoms(self.values)

    @property
    def primary_rank(self) -> int | None:
        """Return the primary rank. Return None when no primary exists."""
        dimension = self._lattice.primary
        if dimension is None:
            return None
        value = dict(self._items)[dimension.code]
        for candidate in getattr(dimension.join, "values", ()):
            if candidate.code == value:
                return candidate.rank
        return None

    def get(self, code: str) -> Any:
        """Return one dimension value."""
        return dict(self._items)[code]

    def __getitem__(self, code: str) -> Any:
        """Return one dimension value."""
        return self.get(code)

    def join(self, other: Label) -> Label:
        """Return the join of this label and another label."""
        self._require_same_lattice(other)
        return Label(self._lattice, self._lattice.join(self.values, other.values))

    def leq(self, other: Label) -> bool:
        """Return True when this label is at most as restrictive as other."""
        self._require_same_lattice(other)
        return self._lattice.leq(self.values, other.values)

    def dominates(self, other: Label) -> bool:
        """Return True when this label is at least as restrictive as other."""
        return other.leq(self)

    def encode(self) -> dict[str, Any]:
        """Return the stored form. The form is stable across processes."""
        return {
            "v": ENCODING_VERSION,
            "values": {code: sorted(value) if isinstance(value, frozenset) else value for code, value in self._items},
        }

    def _require_same_lattice(self, other: Label) -> None:
        if other.signature != self._signature:
            raise LabelError(f"cannot combine labels of {self._signature} and {other._signature}")

    def __eq__(self, other) -> bool:
        """Compare labels by lattice signature and values."""
        if not isinstance(other, Label):
            return NotImplemented
        return self._signature == other._signature and self._items == other._items

    def __hash__(self) -> int:
        """Hash the canonical form."""
        return hash((self._signature, self._items))

    def __repr__(self) -> str:
        """Return a debug string with the values."""
        rendered = ", ".join(
            f"{code}={sorted(value) if isinstance(value, frozenset) else value}" for code, value in self._items
        )
        return f"Label({rendered})"
