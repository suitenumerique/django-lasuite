"""Errors raised by the labels package."""


class LabelError(Exception):
    """Base class for labels errors."""


class JoinError(LabelError):
    """Raised when a join operator or dimension domain is invalid."""


class LabelValueError(LabelError):
    """Raised when a value is not in its dimension domain."""
