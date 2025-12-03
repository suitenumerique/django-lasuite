"""Marketing backends module."""

from dataclasses import dataclass


@dataclass
class ContactData:
    """Contact data for marketing service integration."""

    email: str
    attributes: dict[str, str] | None = None
    list_ids: list[int] | None = None
    update_enabled: bool = True
