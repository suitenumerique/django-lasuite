"""Test the choices for application managing accesses."""

import pytest

from lasuite.drf.models import choices


class DummyChoices(choices.PriorityTextChoices):
    """Dummy choices for testing."""

    ONE = "one", "One"
    TWO = "two", "Two"
    THREE = "three", "Three"


def test_priority_text_choices_get_priotity():
    """Test the get_priority method of the PriorityTextChoices class."""
    assert DummyChoices.get_priority("one") == 1
    assert DummyChoices.get_priority("two") == 2
    assert DummyChoices.get_priority("three") == 3
    assert DummyChoices.get_priority("four") == 0


def test_priority_text_choices_max():
    """Test the max method of the PriorityTextChoices class."""
    assert DummyChoices.max("one", "two", "three") == "three"
    assert DummyChoices.max("one", "three") == "three"
    assert DummyChoices.max("one", "two", "four") == "two"
    assert DummyChoices.max("one", "two", "three", "four") == "three"


@pytest.mark.parametrize(
    ("reach", "role", "select_options"),
    [
        (
            "public",
            "reader",
            {
                "public": ["reader", "editor"],
            },
        ),
        ("public", "editor", {"public": ["editor"]}),
        (
            "authenticated",
            "reader",
            {
                "authenticated": ["reader", "editor"],
                "public": ["reader", "editor"],
            },
        ),
        (
            "authenticated",
            "editor",
            {"authenticated": ["editor"], "public": ["editor"]},
        ),
        (
            "restricted",
            "reader",
            {
                "restricted": None,
                "authenticated": ["reader", "editor"],
                "public": ["reader", "editor"],
            },
        ),
        (
            "restricted",
            "editor",
            {
                "restricted": None,
                "authenticated": ["editor"],
                "public": ["editor"],
            },
        ),
        # Edge cases
        (
            "public",
            None,
            {
                "public": ["reader", "editor"],
            },
        ),
        (
            None,
            "reader",
            {
                "public": ["reader", "editor"],
                "authenticated": ["reader", "editor"],
                "restricted": None,
            },
        ),
        (
            None,
            None,
            {
                "public": ["reader", "editor"],
                "authenticated": ["reader", "editor"],
                "restricted": None,
            },
        ),
    ],
)
def test_models_documents_get_select_options(reach, role, select_options):
    """Validate that the "get_select_options" method operates as expected."""
    assert choices.LinkReachChoices.get_select_options(reach, role) == select_options


@pytest.mark.parametrize(
    ("ancestors_links", "expected_result"),
    [
        (
            [
                {"link_reach": "restricted", "link_role": "public"},
                {"link_reach": "authenticated", "link_role": "editor"},
                {"link_reach": "authenticated", "link_role": "reader"},
            ],
            {"link_reach": "authenticated", "link_role": "editor"},
        ),
        (
            [
                {"link_reach": "restricted", "link_role": "public"},
                {"link_reach": "authenticated", "link_role": "editor"},
                {"link_reach": "public", "link_role": "reader"},
            ],
            {"link_reach": "public", "link_role": "reader"},
        ),
        (
            [
                {"link_reach": "restricted", "link_role": "public"},
                {"link_reach": "authenticated", "link_role": "editor"},
                {"link_reach": "public", "link_role": "reader"},
                {"link_reach": "public", "link_role": "editor"},
            ],
            {"link_reach": "public", "link_role": "editor"},
        ),
    ],
)
def test_models_documents_get_equivalent_link_definition(ancestors_links, expected_result):
    """Test the "get_equivalent_link_definition" method."""
    assert choices.get_equivalent_link_definition(ancestors_links) == expected_result
