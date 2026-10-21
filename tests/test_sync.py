"""Unit tests for the pure reconcile logic (no network)."""

import types

from ldap_keycloak_sync.sync import (
    MARKER_ATTR,
    MARKER_VALUE,
    adopt_payload,
    desired_user,
    diff_update,
    fetch_ldap_users,
    is_protected,
    partition,
)

CFG_SYNC = {
    "mappings": {
        "uid": "username",
        "givenName": "firstName",
        "sn": "lastName",
        "mail": "email",
        "rhatUUID": "rhatUUID",
    },
    "email_verified": True,
    "exclude_users": ["admin"],
    "leaver_action": "disable",
}


def _ldap(uid="jdoe"):
    return {
        "uid": [uid],
        "givenName": ["Jane"],
        "sn": ["Doe"],
        "mail": [f"{uid}@example.com"],
        "rhatUUID": ["abc-123"],
    }


def test_desired_user_routes_fields_and_attrs():
    rep = desired_user(_ldap(), CFG_SYNC)
    assert rep["username"] == "jdoe"
    assert rep["firstName"] == "Jane"
    assert rep["email"] == "jdoe@example.com"
    assert rep["enabled"] is True
    assert rep["emailVerified"] is True
    assert rep["attributes"]["rhatUUID"] == ["abc-123"]
    assert rep["attributes"][MARKER_ATTR] == MARKER_VALUE


def test_diff_update_none_when_unchanged():
    desired = desired_user(_ldap(), CFG_SYNC)
    existing = {"id": "1", **desired}
    assert diff_update(existing, desired) is None  # idempotent -> no write


def test_diff_update_detects_field_change():
    desired = desired_user(_ldap(), CFG_SYNC)
    existing = {"id": "1", **desired, "lastName": "Old"}
    merged = diff_update(existing, desired)
    assert merged is not None
    assert merged["lastName"] == "Doe"


def test_diff_update_preserves_unmanaged_attributes():
    desired = desired_user(_ldap(), CFG_SYNC)
    existing = {
        "id": "1", **desired,
        "attributes": {"somethingElse": ["keep"], "rhatUUID": ["old"]},
    }
    merged = diff_update(existing, desired)
    assert merged["attributes"]["somethingElse"] == ["keep"]  # not clobbered
    assert merged["attributes"]["rhatUUID"] == ["abc-123"]
    assert merged["attributes"][MARKER_ATTR] == MARKER_VALUE


def test_email_lowercased_so_mixed_case_is_idempotent():
    # LDAP mail often has mixed case (e.g. First.Last@example.com); Keycloak stores it lowercased.
    attrs = _ldap()
    attrs["mail"] = ["Jane.DOE@Example.com"]
    desired = desired_user(attrs, CFG_SYNC)
    assert desired["email"] == "jane.doe@example.com"
    existing = {"id": "1", **desired, "email": "jane.doe@example.com"}
    assert diff_update(existing, desired) is None  # no perpetual re-update


def test_username_lowercased():
    # Keycloak lowercases usernames; a mixed-case uid must map to the lowercase key or it
    # mismatches the existing user (create-conflict + wrongful disable).
    rep = desired_user(_ldap("MixedCase1"), CFG_SYNC)
    assert rep["username"] == "mixedcase1"


def test_diff_update_reenables_returning_user():
    desired = desired_user(_ldap(), CFG_SYNC)
    existing = {"id": "1", **desired, "enabled": False}
    merged = diff_update(existing, desired)
    assert merged is not None and merged["enabled"] is True


def test_partition_create_update_leaver():
    desired = {"jdoe": desired_user(_ldap("jdoe"), CFG_SYNC)}
    managed = {MARKER_ATTR: MARKER_VALUE}
    current = [
        {"id": "9", "username": "gone", "enabled": True, "attributes": managed},  # leaver
        {"id": "1", "username": "jdoe", "enabled": True, "attributes": managed, "lastName": "Old"},
    ]
    plan = partition(desired, current, CFG_SYNC)
    assert [u["username"] for u in plan["leavers"]] == ["gone"]
    assert plan["updates"] and plan["updates"][0]["username"] == "jdoe"
    assert plan["creates"] == []

    # new LDAP user not in keycloak -> create
    desired["new"] = desired_user(_ldap("new"), CFG_SYNC)
    plan = partition(desired, current, CFG_SYNC)
    assert [u["username"] for u in plan["creates"]] == ["new"]


def test_leaver_requires_marker_and_enabled():
    desired = {}
    current = [
        {"id": "1", "username": "unmanaged", "enabled": True, "attributes": {}},   # no marker
        {"id": "2", "username": "already-off", "enabled": False,
         "attributes": {MARKER_ATTR: MARKER_VALUE}},
    ]
    assert partition(desired, current, CFG_SYNC)["leavers"] == []


def test_protected_users_untouched():
    assert is_protected("service-account-ldap-sync", [])
    assert is_protected("admin", ["admin"])
    assert not is_protected("jdoe", ["admin"])
    desired = {"admin": desired_user(_ldap("admin"), CFG_SYNC)}
    current = [{"id": "1", "username": "admin", "enabled": True,
                "attributes": {MARKER_ATTR: MARKER_VALUE}}]
    plan = partition(desired, current, CFG_SYNC)
    assert plan == {"creates": [], "updates": [], "leavers": []}


def _fake_ldap_conn(entries):
    std = types.SimpleNamespace(paged_search=lambda **kw: iter(entries))
    return types.SimpleNamespace(extend=types.SimpleNamespace(standard=std))


def test_fetch_ldap_users_keys_by_lowercase_username():
    cfg = {"ldap": {"search_base": "ou=x", "user_filter": "(uid=*)"}, "sync": CFG_SYNC}
    entries = [
        {"type": "searchResEntry", "attributes": _ldap("MixedCase1")},
        {"type": "searchResRef"},  # non-entry rows are ignored
    ]
    desired = fetch_ldap_users(_fake_ldap_conn(entries), cfg)
    assert set(desired) == {"mixedcase1"}
    assert desired["mixedcase1"]["username"] == "mixedcase1"
    assert desired["mixedcase1"]["attributes"]["rhatUUID"] == ["abc-123"]


def test_adopt_payload():
    assert adopt_payload({"username": "x", "attributes": {MARKER_ATTR: MARKER_VALUE}}) is None
    p = adopt_payload({"id": "1", "username": "x", "attributes": {"a": ["b"]}})
    assert p["attributes"] == {"a": ["b"], MARKER_ATTR: MARKER_VALUE}


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all passed")
