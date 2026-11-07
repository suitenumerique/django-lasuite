"""
System checks for the labels module.

The checks test whether this instance can label documents with the active
profile. They run the same contract as the tests.

A missing profile is a warning. The application must boot before an operator
configures a profile.
"""

from __future__ import annotations

from django.core.checks import CheckMessage, Error, register
from django.core.checks import Warning as CheckWarning
from django.db import OperationalError, ProgrammingError

from .errors import LabelError
from .models import LabelProfile, LabelProfileState
from .testing import Violation, check_lattice


def messages_for(violations: list[Violation]) -> list[CheckMessage]:
    """Convert contract violations to Django check messages."""
    messages: list[CheckMessage] = []
    for violation in violations:
        if violation.level == "error":
            messages.append(Error(violation.detail, id="labels.E002", hint=violation.code))
        else:
            messages.append(CheckWarning(violation.detail, id="labels.W002", hint=violation.code))
    return messages


@register()
def check_active_profile(app_configs=None, **kwargs) -> list[CheckMessage]:
    """Validate the active profile when one exists and the database is available."""
    from .compile import active_profile  # noqa: PLC0415  (avoids an import cycle)

    try:
        configured = LabelProfile.objects.filter(state=LabelProfileState.ACTIVE).exists()
    except (OperationalError, ProgrammingError):
        # Not migrated yet, or the database is unreachable. Skip this check.
        return []
    if not configured:
        return [
            CheckWarning(
                "No active label profile is configured.",
                hint="Load a profile or activate one in the admin before labelling documents.",
                id="labels.W001",
            )
        ]
    try:
        compiled = active_profile()
    except LabelError as err:
        # A broken active profile is an error, not a missing profile.
        return [Error(f"The active label profile cannot be compiled: {err}", id="labels.E006")]
    except Exception as err:  # noqa: BLE001  (a check must not crash the check runner)
        return [Error(f"The active label profile cannot be read: {err}", id="labels.E001")]

    messages = messages_for(check_lattice(compiled.lattice))
    if compiled.lattice.primary is None:
        messages.append(
            Error(
                f"Profile {compiled.code!r} has no primary dimension.",
                hint="The indexed rank column is derived from it, so list filtering "
                "and staleness detection would silently stop working.",
                id="labels.E005",
            )
        )
    if not compiled.ceiling:
        messages.append(
            CheckWarning(
                f"Profile {compiled.code!r} declares no ceiling.",
                hint="Without a ceiling, nothing prevents labelling above what this instance is allowed to hold.",
                id="labels.W003",
            )
        )
    return messages
