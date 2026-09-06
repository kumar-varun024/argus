"""Unit tests for the extracted mission scope-derivation helper."""
import pytest

from argus.mission.scope import derive_default_scope
from argus.runtime.mission import _derive_default_scope


def test_backcompat_alias_is_same_callable():
    # runtime.mission re-exports the helper under its historical private name.
    assert _derive_default_scope is derive_default_scope


@pytest.mark.parametrize(
    "target,expected",
    [
        ("example.com", ["example.com", "*.example.com"]),
        ("https://example.com", ["example.com", "*.example.com"]),
        ("https://api.example.com:8080/path", ["api.example.com", "*.api.example.com"]),
        ("api.example.com:8080", ["api.example.com", "*.api.example.com"]),
        ("*.example.com", ["*.example.com", "example.com"]),
        ("10.0.0.0/24", ["10.0.0.0/24"]),
        ("192.168.1.1", ["192.168.1.1"]),
        ("example.com/api", ["example.com", "*.example.com"]),
        ("", []),
        ("   ", []),
    ],
)
def test_derive_default_scope(target, expected):
    assert derive_default_scope(target) == expected


def test_non_string_returns_empty():
    assert derive_default_scope(None) == []  # type: ignore[arg-type]


def test_ipv6_brackets_stripped():
    assert derive_default_scope("[::1]:9000") == ["::1"]


def test_mission_uses_derived_scope():
    from argus.runtime.mission import Mission

    m = Mission(target="example.com")
    assert m.scope == ["example.com", "*.example.com"]
