"""
Contract checks for label profiles.

This is a general purpose diagnostic system for boot tests, during profile
loads or even CI.

To avoid materializing very wide products, some techniques are used here to
sample the correctness of the profile when it is too large.

Instances with large products are unlikely to happen but it doesn't cost much
to support this case.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from itertools import combinations, product
from typing import Any, Literal

from .errors import LabelError
from .joins import BOOL, SUBSET
from .lattice import Lattice, Values

#: Maximum number of labels to materialize before thinning. A large product
#: can make a boot check slow.
MAX_PRODUCT = 192

#: Below this, a dimension cannot be thinned any further without losing its extremes.
MIN_PER_DIMENSION = 2


@dataclass(frozen=True)
class Violation:
    """One profile contract violation."""

    code: str
    detail: str
    level: Literal["error", "warning"] = "error"

    def __str__(self) -> str:
        """Render for Django checks and command output."""
        return f"{self.level}: {self.code}: {self.detail}"


class ContractError(LabelError):
    """Raised when a profile violates the contract."""

    def __init__(self, violations: Sequence[Violation]):
        """Store all violations."""
        self.violations = tuple(violations)
        details = "; ".join(str(violation) for violation in self.violations)
        super().__init__(f"profile does not satisfy the lattice contract: {details}")


def _powerset(items: Sequence[str]) -> list[frozenset[str]]:
    return [frozenset(combination) for size in range(len(items) + 1) for combination in combinations(items, size)]


def _evenly(values: Sequence[Any], size: int) -> list[Any]:
    """Return size values, spread evenly. Keep both extremes."""
    if len(values) <= size:
        return list(values)
    if size <= 1:
        return [values[0]]
    stride = (len(values) - 1) / (size - 1)
    picked = [values[round(index * stride)] for index in range(size)]
    unique: list[Any] = []
    for value in picked:
        if value not in unique:
            unique.append(value)
    return unique


def dimension_samples(dimension, limit: int) -> list[Any]:
    """Return a bounded, deterministic set of values for one dimension."""
    if dimension.join.domain == BOOL:
        return [False, True]
    codes = [value.code for value in dimension.join.values]
    if dimension.join.domain == SUBSET:
        subsets = _powerset(codes)
        if len(subsets) > limit:
            subsets = [frozenset(), frozenset(codes)] + [frozenset({code}) for code in codes]
        return subsets[: max(limit, 2)]
    return _evenly(codes, max(limit, 2))


def sampling_plan(lattice: Lattice, limit: int = 24) -> list[list[Any]]:
    """Return the sample values for each dimension."""
    budget = MAX_PRODUCT
    plan = [dimension_samples(dimension, max(limit, 2)) for dimension in lattice.dimensions]
    while math.prod(len(samples) for samples in plan) > budget:
        widest = max(range(len(plan)), key=lambda index: len(plan[index]))
        if len(plan[widest]) <= MIN_PER_DIMENSION:
            break
        plan[widest] = _evenly(plan[widest], len(plan[widest]) // 2)
    return plan


def sample_labels(lattice: Lattice, limit: int = 24) -> list[dict[str, Any]]:
    """Return a deterministic label sample. Include both extremes."""
    labels: list[dict[str, Any]] = [
        dict(zip(lattice.codes, combination, strict=True)) for combination in product(*sampling_plan(lattice, limit))
    ]
    if len(labels) <= limit:
        return labels

    # Thin deterministically: keep both extremes, then use a fixed stride.
    kept = [labels[0], lattice.top(), lattice.bottom()]
    stride = max(1, len(labels) // max(limit - len(kept), 1))
    kept.extend(labels[::stride])
    unique: list[dict[str, Any]] = []
    for label in kept:
        if label not in unique:
            unique.append(label)
    return unique[:limit]


def iter_pairs(labels: Sequence[Values]) -> Iterator[tuple[Values, Values]]:
    """Yield every ordered pair."""
    for left in labels:
        for right in labels:
            yield left, right


def _check_pairwise(lattice: Lattice, labels: Sequence[Values]) -> list[Violation]:
    """Check the laws that need two labels."""
    violations: list[Violation] = []
    for left, right in iter_pairs(labels):
        if lattice.join(left, right) != lattice.join(right, left):
            violations.append(Violation("lattice.commutativity", f"join({left}, {right}) is not symmetric"))
            return violations
        if lattice.leq(left, right) != (lattice.join(left, right) == right):
            violations.append(Violation("lattice.order", f"order of {left} and {right} disagrees with the join"))
            return violations
        if lattice.atoms(lattice.join(left, right)) != lattice.atoms(left) | lattice.atoms(right):
            violations.append(Violation("lattice.atoms", f"atoms of join({left}, {right}) are not the union"))
            return violations
        if lattice.leq(left, right) != (lattice.atoms(left) <= lattice.atoms(right)):
            violations.append(Violation("lattice.atoms", f"atom containment disagrees with order on {left}"))
            return violations
    return violations


def _check_associativity(lattice: Lattice, labels: Sequence[Values]) -> list[Violation]:
    """Check that grouping does not change a join."""
    for first in labels:
        for second in labels:
            for third in labels:
                nested = lattice.join(lattice.join(first, second), third)
                flat = lattice.join(first, lattice.join(second, third))
                if nested != flat:
                    return [
                        Violation(
                            "lattice.associativity",
                            f"join is not associative on {first}, {second}, {third}",
                        )
                    ]
    return []


def _check_single(lattice: Lattice, labels: Sequence[Values]) -> list[Violation]:
    """Check the laws that need one label."""
    violations: list[Violation] = []
    for label in labels:
        if lattice.join(label, label) != label:
            violations.append(Violation("lattice.idempotence", f"join({label}, {label}) moves"))
        if not lattice.leq(lattice.bottom(), label) or not lattice.leq(label, lattice.top()):
            violations.append(Violation("lattice.bounds", f"{label} is not between bottom and top"))
        if lattice.join(lattice.top(), label) != lattice.top():
            violations.append(Violation("lattice.bounds", f"top is not absorbing for {label}"))
        try:
            decoded = lattice.from_atoms(lattice.atoms(label))
        except LabelError as err:
            violations.append(Violation("lattice.atoms", f"{label} does not decode: {err}"))
            continue
        if decoded != label:
            violations.append(Violation("lattice.atoms", f"{label} decodes to {decoded}"))
    return violations


def _check_atom_budget(lattice: Lattice, atom_budget: int) -> list[Violation]:
    """Warn when a label needs too many atoms."""
    budget = lattice.atoms_per_label()
    if budget <= atom_budget:
        return []
    return [
        Violation(
            "lattice.atom_budget",
            f"a label may need {budget} atoms, above the budget of {atom_budget}; "
            "filtering will be expensive and another encoding should be considered",
            level="warning",
        )
    ]


def check_lattice(lattice: Lattice, limit: int = 24, atom_budget: int = 64) -> list[Violation]:
    """Return all contract violations for a profile."""
    labels = sample_labels(lattice, limit=limit)
    return [
        *_check_pairwise(lattice, labels),
        *_check_associativity(lattice, labels),
        *_check_single(lattice, labels),
        *_check_atom_budget(lattice, atom_budget),
    ]


def assert_lattice_contract(lattice: Lattice, limit: int = 24, atom_budget: int = 64) -> None:
    """Raise ContractError when the profile violates the contract."""
    violations = check_lattice(lattice, limit=limit, atom_budget=atom_budget)
    errors = [violation for violation in violations if violation.level == "error"]
    if errors:
        raise ContractError(errors)
