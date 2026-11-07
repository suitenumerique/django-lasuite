"""
Compile the active profile once per process.

Request paths must not query the profile. This module compiles the active
profile into an immutable object and caches it in the process. The cache key
uses the profile digest.

Other processes may publish a new profile. The cache checks the shared digest
after a short interval. Set LABELS_CACHE_TTL to zero to disable the interval.

A cache failure is not fatal. The database remains the source of truth.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.cache import cache

from .errors import LabelError
from .label import Label
from .lattice import Lattice
from .models import LabelProfile, LabelProfileState

logger = logging.getLogger("lasuite.labels")

CACHE_KEY = "lasuite.labels.active_profile_hash"

#: Seconds a process keeps a cached profile before it checks the shared digest.
DEFAULT_TTL = 30

#: How many distinct digests a process keeps, so a publication does not leak.
LOCAL_CACHE_SIZE = 8


@dataclass(frozen=True)
class CompiledProfile:
    """Profile data needed at request time."""

    profile_id: str
    code: str
    version: int
    content_hash: str
    ceiling: str
    lattice: Lattice
    dimensions_spec: tuple[dict[str, Any], ...] = ()

    @property
    def cache_key(self) -> str:
        """Return the cache key for this profile version."""
        return f"{self.profile_id}:{self.content_hash}"

    def ceiling_label(self) -> Label | None:
        """
        Return the instance ceiling as a full label, or None.

        The profile stores only the primary value. Every other dimension uses
        its top value. This allows a target such as TS+SF+compartment below
        the ceiling. A missing primary is a profile error.
        """
        if not self.ceiling:
            return None
        primary = self.lattice.primary
        if primary is None:
            raise LabelError("a profile with a ceiling needs a primary dimension")
        values = self.lattice.top()
        values[primary.code] = self.ceiling
        return Label(self.lattice, values)


_local: dict[str, CompiledProfile] = {}
_current: CompiledProfile | None = None
_checked_at: float = 0.0


def compile_profile(profile: LabelProfile) -> CompiledProfile:
    """Build the immutable profile object from a stored profile."""
    return CompiledProfile(
        profile_id=str(profile.pk),
        code=profile.code,
        version=profile.version,
        content_hash=profile.content_hash or profile.compute_content_hash(),
        ceiling=profile.ceiling,
        lattice=profile.to_lattice(),
        dimensions_spec=tuple(dimension.to_spec() for dimension in profile.dimensions.all()),
    )


def clear() -> None:
    """Clear local and shared caches."""
    global _current  # noqa: PLW0603
    _local.clear()
    _current = None
    reset_check_interval()
    try:
        cache.delete(CACHE_KEY)
    except Exception as err:
        logger.debug("labels: cannot clear the profile digest: %s", err)


def reset_check_interval() -> None:
    """Force the next call to read the shared digest."""
    global _checked_at  # noqa: PLW0603  (module-level clock)
    _checked_at = 0.0


def _interval() -> int:
    return int(getattr(settings, "LABELS_CACHE_TTL", DEFAULT_TTL))


def _remember(profile: CompiledProfile) -> CompiledProfile:
    global _current  # noqa: PLW0603
    if len(_local) >= LOCAL_CACHE_SIZE:
        _local.pop(next(iter(_local)))
    _local[profile.content_hash] = profile
    _current = profile
    return profile


def _store_hash(content_hash: str) -> None:
    try:
        cache.set(CACHE_KEY, content_hash, _interval() or None)
    except Exception as err:
        logger.debug("labels: cannot publish the profile digest: %s", err)


def _stored_hash() -> str | None:
    try:
        return cache.get(CACHE_KEY)
    except Exception as err:
        logger.debug("labels: cannot read the profile digest: %s", err)
        return None


def active_profile(*, force: bool = False) -> CompiledProfile:
    """Return the compiled active profile, recompiling only when it changed."""
    global _checked_at  # noqa: PLW0603

    elapsed = time.monotonic() - _checked_at
    if not force and _checked_at and elapsed < _interval() and _current is not None:
        return _current

    stored_hash = None if force else _stored_hash()
    if stored_hash and stored_hash in _local:
        _checked_at = time.monotonic()
        return _remember(_local[stored_hash])

    profile = LabelProfile.objects.filter(state=LabelProfileState.ACTIVE).prefetch_related("dimensions").first()
    if profile is None:
        raise LabelError("no active label profile is configured")

    compiled = _remember(compile_profile(profile))
    _store_hash(compiled.content_hash)
    _checked_at = time.monotonic()
    return compiled
