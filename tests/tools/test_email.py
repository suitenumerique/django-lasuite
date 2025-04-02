"""Tests for email tools."""

import pytest

from lasuite.tools.email import get_domain_from_email


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("user@example.com", "example.com"),
        ("test.user@sub.domain.co.uk", "sub.domain.co.uk"),
        ("name+tag@gmail.com", "gmail.com"),
        ("user@localhost", "localhost"),
        ("user@127.0.0.1", "127.0.0.1"),
    ],
)
def test_get_domain_from_email_valid(email, expected):
    """Test extracting domain from valid email addresses."""
    assert get_domain_from_email(email) == expected


@pytest.mark.parametrize(
    "invalid_email",
    [
        None,
        "",
        "invalid-email",
        "user@",
        "@domain.com",
        "user@domain@com",
        "user@@domain.com",
        "user domain.com",
        "<script>alert('XSS')</script>@example.com",
        "user@example.com\n",
        "user@example.com;drop table users",
    ],
)
def test_get_domain_from_email_invalid(invalid_email):
    """Test handling of invalid email addresses."""
    assert get_domain_from_email(invalid_email) is None


def test_get_domain_from_email_length_limits():
    """Test handling of extremely long email addresses."""
    # Very long local part (should fail)
    long_local = "a" * 65 + "@example.com"
    assert get_domain_from_email(long_local) is None

    # Very long domain (valid according to standards)
    domain_parts = ".".join(["a" * 64] * 4)
    long_domain = f"user@{domain_parts}"
    # This might fail depending on email validation implementation
    # The test expects None since such domains aren't typically valid in practice
    assert get_domain_from_email(long_domain) is None
