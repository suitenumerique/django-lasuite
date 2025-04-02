"""Email related tools."""

from email.errors import HeaderParseError
from email.headerregistry import Address


def get_domain_from_email(email: str | None) -> str | None:
    """Extract domain from email."""
    try:
        address = Address(addr_spec=email)
        if len(address.username) > 64 or len(address.domain) > 255:  # noqa: PLR2004
            # Simple length validation using the RFC 5321 limits
            return None
        if not address.domain:
            # If the domain is empty, return None
            return None
        return address.domain
    except (ValueError, AttributeError, IndexError, HeaderParseError):
        return None
