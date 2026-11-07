"""
Persistence for the label system.

This module stores three records:

- ``LabelProfile``: the label taxonomy and its deployment limits.
- ``LabelDimension``: one axis of that taxonomy.
- ``LabelAuditEvent``: the append-only journal of labelling acts.

The module stores and validates these records. It does not enforce access
control. The application keeps its own access rules. A label records what a
document is.

Integration with an application
-------------------------------
The application owns the document or item model. The model inherits
``LabeledMixin`` from ``lasuite.labels.mixins``. The mixin adds the label
fields and derives the indexed columns when the row is saved.

The deployment owns one profile file. The release process loads it with
``labels_load_profile --file ... --activate``. The package does not ship a
production profile.

The application declares its labelled models in ``LABELS_LABELLED_MODELS`` and
its hierarchy in ``LABELS_SCOPE_PROVIDERS``. The provider returns the ancestor
scopes of a page.

The application writes labels through the write service or the label API. The
service checks authority and writes the audit event in the same transaction.

The application reads labels through the serializer mixin or the profile API.
The payload contains state, values, display keys, suggestion and decision. It
does not contain prose.

JSON columns and performance
----------------------------
``LabelDimension.values`` stores the full domain in one JSON column. The code
reads the domain as a whole. It does not filter rows by a value inside the
domain. A table for each value would add joins, migrations and rows, but it
would not help a query.

The label value, the previous value in the journal, and the actor clearance
also use JSON. The code reads and writes each of them as one document.

List filters do not use JSON. They use separate scalar columns:
``label_state``, ``label_primary_rank`` and ``label_atoms_text``. These columns
are indexed. This keeps list queries fast.

Do not use JSON for a field that becomes a query key. Promote that field to a
scalar column or to an indexed expression.

Typical use cases
-----------------
1. A deployment loads a corporate, ministry or defense profile.
2. An instance operator edits a draft profile, then activates it.
3. An application labels a document or folder. Its children inherit the label.
4. A user with the owner or administrator role raises, lowers or clears a
   label. The journal records the act.
5. A list filters by primary rank or by atom containment.
6. An auditor reads the journal or uses ``labels_verify`` to find drift.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from .errors import LabelError
from .joins import BOOL, CHAIN, Value, join_for, join_registry
from .lattice import Lattice

#: Dimension fields that change the meaning of existing labels. Display keys
#: are excluded. A rename is cosmetic. A reorder changes meaning.
SEMANTIC_DIMENSION_FIELDS = ("code", "join", "is_primary", "values")


def canonical_json(payload: Any) -> str:
    """Serialize a payload with a stable order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class LabelProfileState(models.TextChoices):
    """A profile is a draft until activation. An active profile is frozen."""

    DRAFT = "draft", _("Draft")
    ACTIVE = "active", _("Active")


class LabelProfile(models.Model):
    """A label profile: lattice, ceiling and display keys."""

    id = models.UUIDField(
        help_text=_("primary key for the record as UUID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    created_at = models.DateTimeField(
        help_text=_("date and time at which a record was created"),
        auto_now_add=True,
        editable=False,
    )
    updated_at = models.DateTimeField(
        help_text=_("date and time at which a record was last updated"),
        auto_now=True,
        editable=False,
    )
    code = models.SlugField(
        help_text=_("stable identifier of this profile, e.g. igi1300"),
        max_length=64,
        unique=True,
    )
    name = models.CharField(help_text=_("human readable name"), max_length=255)
    state = models.CharField(
        help_text=_("a draft can be edited, an active profile cannot"),
        max_length=16,
        choices=LabelProfileState.choices,
        default=LabelProfileState.DRAFT,
    )
    ceiling = models.CharField(
        help_text=_("the most restrictive value of the primary dimension this instance may store"),
        max_length=64,
        blank=True,
    )
    content_hash = models.CharField(
        help_text=_("digest of the semantic fields, used to detect drift"),
        max_length=64,
        blank=True,
        editable=False,
    )
    version = models.PositiveIntegerField(
        help_text=_("incremented every time a semantic change is published"),
        default=1,
    )

    class Meta:
        """Allow one active profile. Use a stable order."""

        ordering = ["code"]
        constraints = [
            models.UniqueConstraint(
                fields=["state"],
                condition=Q(state=LabelProfileState.ACTIVE),
                name="labels_one_active_profile",
            ),
        ]
        verbose_name = _("label profile")
        verbose_name_plural = _("label profiles")

    def __str__(self):
        """Return the profile code and state."""
        return f"{self.code} ({self.state})"

    def save(self, *args, **kwargs):
        """Validate the profile and refresh its digest."""
        self.full_clean()
        super().save(*args, **kwargs)
        self.refresh_content_hash()

    @property
    def is_active(self) -> bool:
        """Return True when this profile is active."""
        return self.state == LabelProfileState.ACTIVE

    def dimensions_spec(self) -> list[dict[str, Any]]:
        """Return the declarative form of all dimensions."""
        return [dimension.to_spec() for dimension in self.dimensions.all()]

    def semantic_payload(self) -> dict[str, Any]:
        """Return the fields that identify this profile version."""
        return {
            "code": self.code,
            # Include the version so a version bump invalidates compiled caches
            # even when the semantic fields do not change.
            "version": self.version,
            "ceiling": self.ceiling,
            "dimensions": [dimension.semantic() for dimension in self.dimensions.all()],
        }

    def compute_content_hash(self) -> str:
        """Return the digest of the profile identity and semantic fields."""
        return hashlib.sha256(canonical_json(self.semantic_payload()).encode()).hexdigest()

    def refresh_content_hash(self) -> str:
        """Recompute and store the digest. Clear the compile cache when it changes."""
        digest = self.compute_content_hash()
        if digest != self.content_hash:
            type(self).objects.filter(pk=self.pk).update(content_hash=digest)
            self.content_hash = digest
            # Import here: the compile module imports this module.
            from . import compile as labels_compile  # noqa: PLC0415

            labels_compile.clear()
        return digest

    def to_lattice(self) -> Lattice:
        """Build the lattice from the stored dimensions."""
        return Lattice.from_spec(self.dimensions_spec())

    def clean(self):
        """Reject a profile that cannot compile or cannot be enforced."""
        errors: dict[str, str] = {}
        dimensions = list(self.dimensions.all()) if self.pk else []
        if self.state == LabelProfileState.ACTIVE:
            errors.update(self._clean_active(dimensions))
        if self.ceiling and dimensions:
            errors.update(self._clean_ceiling(dimensions))
        if errors:
            raise ValidationError(errors)

    def _clean_active(self, dimensions: Iterable[LabelDimension]) -> dict[str, str]:
        errors: dict[str, str] = {}
        if not dimensions:
            errors["state"] = _("An active profile needs at least one dimension.")
            return errors
        primaries = [dimension for dimension in dimensions if dimension.is_primary]
        if len(primaries) != 1:
            errors["state"] = _("Exactly one dimension must be primary, found %(count)d.") % {"count": len(primaries)}
        return errors

    def _clean_ceiling(self, dimensions: Iterable[LabelDimension]) -> dict[str, str]:
        primary = next((dimension for dimension in dimensions if dimension.is_primary), None)
        if primary is None:
            return {"ceiling": _("A ceiling needs a primary dimension to refer to.")}
        codes = [value.get("code") for value in primary.values if isinstance(value, dict)]
        if self.ceiling not in codes:
            return {
                "ceiling": _("%(ceiling)s is not a value of the primary dimension %(code)s.")
                % {"ceiling": self.ceiling, "code": primary.code}
            }
        return {}


class LabelDimension(models.Model):
    """One profile dimension with a join operator and domain."""

    id = models.UUIDField(
        help_text=_("primary key for the record as UUID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    profile = models.ForeignKey(
        LabelProfile,
        help_text=_("the profile this axis belongs to"),
        related_name="dimensions",
        on_delete=models.CASCADE,
    )
    code = models.SlugField(help_text=_("stable identifier of this axis, e.g. tier"), max_length=64)
    join = models.CharField(
        help_text=_("join operator, one of the codes registered in LABELS_JOINS"),
        max_length=64,
    )
    is_primary = models.BooleanField(
        help_text=_("the dimension whose rank is indexed for list filtering"),
        default=False,
    )
    label_key = models.CharField(
        help_text=_("translation key of the axis name, e.g. igi1300.tier"),
        max_length=255,
    )
    values = models.JSONField(
        help_text=_("declared domain: code, rank, label_key and regime per value"),
        default=list,
        blank=True,
    )

    class Meta:
        """Allow one dimension code per profile. Use a stable order."""

        ordering = ["profile", "code"]
        constraints = [
            models.UniqueConstraint(fields=["profile", "code"], name="labels_unique_dimension_code"),
        ]
        verbose_name = _("label dimension")
        verbose_name_plural = _("label dimensions")

    def __str__(self):
        """Return profile.dimension and the join code."""
        return f"{self.profile.code}.{self.code} ({self.join})"

    def save(self, *args, **kwargs):
        """Validate the dimension and refresh the profile digest."""
        self.full_clean()
        super().save(*args, **kwargs)
        self.profile.refresh_content_hash()

    def delete(self, *args, **kwargs):
        """Delete the dimension and refresh the profile digest."""
        profile = self.profile
        result = super().delete(*args, **kwargs)
        if profile.pk:
            profile.refresh_content_hash()
        return result

    def declared_values(self) -> tuple[Value, ...]:
        """Return the domain values for the join registry."""
        declared = []
        for entry in self.values if isinstance(self.values, list) else ():
            if not isinstance(entry, dict) or not entry.get("code"):
                raise LabelError(f"dimension {self.code!r} has a value without a code: {entry!r}")
            declared.append(Value(code=entry["code"], rank=entry.get("rank")))
        return tuple(declared)

    def operator(self):
        """Return the join operator for this dimension."""
        return join_for(self.join, self.declared_values())

    def to_spec(self) -> dict[str, Any]:
        """Return the declarative form used to build the lattice."""
        for entry in self.values if isinstance(self.values, list) else ():
            if not isinstance(entry, dict) or not entry.get("code"):
                raise LabelError(f"dimension {self.code!r} has a value without a code: {entry!r}")
        return {
            "code": self.code,
            "join": self.join,
            "is_primary": self.is_primary,
            "values": sorted(
                (dict(entry) for entry in self.values),
                key=lambda entry: (entry.get("rank") is None, entry.get("rank") or 0, entry["code"]),
            ),
        }

    def semantic(self) -> tuple[Any, ...]:
        """Return the fields that change label meaning."""
        return (
            self.code,
            self.join,
            self.is_primary,
            canonical_json(
                sorted(
                    (
                        {"code": entry["code"], "rank": entry.get("rank"), "regime": entry.get("regime")}
                        for entry in self.values
                    ),
                    key=lambda entry: entry["code"],
                )
            ),
        )

    def clean(self):
        """Validate the domain and the operator."""
        errors: dict[str, str] = {}
        if not self.label_key:
            errors["label_key"] = _("A dimension needs a translation key.")
        errors.update(self._clean_join_code())
        value_errors = self._clean_values() if "join" not in errors else {}
        errors.update(value_errors)
        if not errors:
            errors.update(self._clean_operator())
        if errors:
            raise ValidationError(errors)

    def _clean_join_code(self) -> dict[str, str]:
        if self.join in join_registry():
            return {}
        available = ", ".join(sorted(join_registry()))
        return {
            "join": _("%(join)s is not a registered operator: %(available)s.")
            % {"join": self.join, "available": available}
        }

    def _clean_values(self) -> dict[str, str]:
        operator = join_registry().get(self.join)
        if operator is not None and operator.domain == BOOL:
            if self.values:
                return {"values": _("A boolean dimension declares an implicit domain and no values.")}
            return {}
        if not isinstance(self.values, list) or not self.values:
            return {"values": _("A dimension needs at least one declared value.")}
        codes = []
        for entry in self.values:
            if not isinstance(entry, dict) or not entry.get("code"):
                return {"values": _("Every value needs a code.")}
            codes.append(entry["code"])
        if len(set(codes)) != len(codes):
            return {"values": _("Value codes must be unique: %(codes)s.") % {"codes": sorted(codes)}}
        return {}

    def _clean_operator(self) -> dict[str, str]:
        try:
            operator = self.operator()
        except LabelError as err:
            return {"values": str(err)}
        if self.is_primary and operator.domain != CHAIN:
            return {
                "is_primary": _("Only a chain can be the primary dimension, %(join)s is a %(domain)s.")
                % {"join": self.join, "domain": operator.domain}
            }
        return {}


class LabelAuditAction(models.TextChoices):
    """Actions that the journal records."""

    ASSIGN = "assign", _("Assign")
    RAISE = "raise", _("Raise")
    LOWER = "lower", _("Lower")
    LOAD = "load", _("Load a profile")


class LabelAuditSource(models.TextChoices):
    """Source of the label value."""

    MANUAL = "manual", _("Chosen by a person")
    INHERITED = "inherited", _("Inherited from a parent")
    LOAD = "load", _("Loaded from a file")


class LabelAuditEvent(models.Model):
    """Append-only journal of labelling acts."""

    id = models.UUIDField(
        help_text=_("primary key for the record as UUID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    created_at = models.DateTimeField(
        help_text=_("date and time at which the act happened"),
        auto_now_add=True,
        editable=False,
        db_index=True,
    )
    action = models.CharField(help_text=_("what was done"), max_length=16, choices=LabelAuditAction.choices)
    source = models.CharField(
        help_text=_("where the value came from"),
        max_length=16,
        choices=LabelAuditSource.choices,
        default=LabelAuditSource.MANUAL,
    )
    model_label = models.CharField(help_text=_("the labelled model, e.g. core.Document"), max_length=255)
    object_id = models.CharField(help_text=_("the labelled object"), max_length=64)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        help_text=_("who acted, null when the actor is gone"),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    actor_clearance = models.JSONField(
        help_text=_("the actor's clearance at the time of the act, if known"),
        null=True,
        blank=True,
    )
    previous = models.JSONField(help_text=_("the label before the act"), null=True, blank=True)
    label = models.JSONField(help_text=_("the label after the act"), null=True, blank=True)
    profile_version = models.PositiveIntegerField(
        help_text=_("the profile version the act was performed under"), default=0
    )
    reason_code = models.CharField(
        help_text=_("machine readable reason, e.g. labels.authority.clearance"),
        max_length=128,
        blank=True,
    )
    justification = models.TextField(help_text=_("free text written by a person, never rendered as a code"), blank=True)
    request_id = models.CharField(
        help_text=_("correlation id of the request that produced the act"),
        max_length=64,
        blank=True,
    )

    class Meta:
        """Newest first. Index per object."""

        ordering = ["-created_at"]
        indexes = [models.Index(fields=["model_label", "object_id"], name="labels_audit_object")]
        verbose_name = _("label audit event")
        verbose_name_plural = _("label audit events")

    def __str__(self):
        """Return action, model and object."""
        return f"{self.action} {self.model_label}:{self.object_id}"

    def save(self, *args, **kwargs):
        """Raise LabelError when the event is not new."""
        if not self._state.adding:
            raise LabelError("label audit events are append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Raise LabelError. The journal is append-only."""
        raise LabelError("label audit events are append-only")
