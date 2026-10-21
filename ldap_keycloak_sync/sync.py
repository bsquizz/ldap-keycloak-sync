"""Reconcile Keycloak realm users against an LDAP search result.

Pure functions (desired_user / diff_update / partition / is_protected / adopt_payload) hold
all the decision logic and take plain dicts, so they are unit-tested without a network. The
*_run entry points wrap them with the python-keycloak and ldap3 clients.
"""

from __future__ import annotations

import logging
import ssl
import sys
from collections import Counter

log = logging.getLogger("ldap_keycloak_sync")

# Top-level UserRepresentation fields; any other mapping target is a custom attribute.
TOP_LEVEL_FIELDS = {"username", "firstName", "lastName", "email", "emailVerified", "enabled"}
# Attribute marking a user as owned by this tool. Only marked users are ever disabled/deleted.
MARKER_ATTR = "managedByLdapSync"
MARKER_VALUE = ["true"]


# --------------------------------------------------------------------------- pure logic

def is_protected(username: str, exclude_users) -> bool:
    """Users the tool must never create, update, disable, delete, or adopt."""
    return username.startswith("service-account-") or username in set(exclude_users)


def desired_user(ldap_attrs: dict, cfg_sync: dict) -> dict:
    """Build the desired Keycloak representation for one in-scope LDAP entry.

    `ldap_attrs` maps ldap attribute name -> list of values (ldap3 form).
    Returns a partial UserRepresentation containing only managed fields/attributes.
    """
    mappings = cfg_sync["mappings"]
    fields, attrs = {}, {}
    for ldap_attr, target in mappings.items():
        vals = ldap_attrs.get(ldap_attr) or []
        if not isinstance(vals, list):
            vals = [vals]
        if not vals:
            continue
        if target in TOP_LEVEL_FIELDS:
            fields[target] = str(vals[0])
        else:
            attrs[target] = [str(v) for v in vals]

    rep = dict(fields)
    rep["enabled"] = True  # in scope -> enabled (creates and re-enables returning users)
    if cfg_sync.get("email_verified", True) and rep.get("email"):
        rep["emailVerified"] = True
    attrs[MARKER_ATTR] = MARKER_VALUE
    rep["attributes"] = attrs
    return rep


def diff_update(existing: dict, desired: dict) -> dict | None:
    """Merge `desired` onto a copy of the existing rep; return it if anything changed, else None.

    Only managed top-level fields and managed attribute keys are touched. Unmanaged attributes
    are preserved; credentials and role/group mappings live on other REST resources and are
    never present here.
    """
    merged = dict(existing)
    changed = False

    for field, value in desired.items():
        if field == "attributes":
            continue
        if existing.get(field) != value:
            merged[field] = value
            changed = True

    existing_attrs = existing.get("attributes") or {}
    merged_attrs = dict(existing_attrs)
    for key, value in desired.get("attributes", {}).items():
        if existing_attrs.get(key) != value:
            merged_attrs[key] = value
            changed = True
    merged["attributes"] = merged_attrs

    return merged if changed else None


def partition(desired: dict, current: list, cfg_sync: dict) -> dict:
    """Split work into create / update / leaver lists from in-memory state.

    `desired`: {username: desired_rep}. `current`: list of Keycloak user reps.
    Protected users are dropped from both sides first.
    """
    exclude = cfg_sync.get("exclude_users", [])
    current_by_name = {
        u["username"]: u for u in current if not is_protected(u["username"], exclude)
    }
    desired = {n: r for n, r in desired.items() if not is_protected(n, exclude)}

    creates = [r for n, r in desired.items() if n not in current_by_name]

    updates = []
    for name, rep in desired.items():
        existing = current_by_name.get(name)
        if existing is not None:
            merged = diff_update(existing, rep)
            if merged is not None:
                updates.append(merged)

    leavers = [
        u for name, u in current_by_name.items()
        if name not in desired
        and (u.get("attributes") or {}).get(MARKER_ATTR) == MARKER_VALUE
        and u.get("enabled", False)
    ]
    return {"creates": creates, "updates": updates, "leavers": leavers}


def adopt_payload(user: dict) -> dict | None:
    """Return a minimal update adding the ownership marker, or None if already marked."""
    attrs = user.get("attributes") or {}
    if attrs.get(MARKER_ATTR) == MARKER_VALUE:
        return None
    merged = dict(user)
    merged["attributes"] = {**attrs, MARKER_ATTR: MARKER_VALUE}
    return merged


# --------------------------------------------------------------------------- I/O

def connect_keycloak(cfg: dict):
    from keycloak import KeycloakAdmin, KeycloakOpenIDConnection

    kc = cfg["keycloak"]
    common = dict(server_url=kc["url"], realm_name=kc["realm"], verify=kc.get("verify", True))
    if kc.get("client_secret"):
        conn = KeycloakOpenIDConnection(
            client_id=kc.get("client_id", "ldap-sync"),
            client_secret_key=kc["client_secret"],
            **common,
        )
    else:
        conn = KeycloakOpenIDConnection(
            client_id=kc.get("client_id", "admin-cli"),
            username=kc["username"],
            password=kc["password"],
            user_realm_name=kc.get("user_realm_name", "master"),
            **common,
        )
    admin = KeycloakAdmin(connection=conn)

    # Realm must exist; users/count 404s otherwise and only needs view-users.
    from keycloak.exceptions import KeycloakGetError
    try:
        admin.users_count()
    except KeycloakGetError as e:
        if getattr(e, "response_code", None) == 404:
            sys.exit(f"FATAL: realm '{kc['realm']}' not found in Keycloak")
        raise
    _assert_marker_persists(admin)
    return admin


def _assert_marker_persists(admin) -> None:
    """Fail fast if the ownership marker would be silently dropped.

    With the declarative user profile and `unmanagedAttributePolicy` unset, Keycloak discards
    attributes that aren't declared -- which would quietly break disable-on-leave.
    """
    try:
        profile = admin.get_realm_users_profile()
    except Exception as e:  # noqa: BLE001 - don't block if the profile can't be read
        log.warning("could not verify '%s' is declared in the user profile: %s", MARKER_ATTR, e)
        return
    declared = {a.get("name") for a in profile.get("attributes", [])}
    if MARKER_ATTR in declared or profile.get("unmanagedAttributePolicy"):
        return
    sys.exit(
        f"FATAL: realm user profile does not declare '{MARKER_ATTR}' and unmanaged attributes are "
        f"disabled, so the ownership marker would be silently dropped. Declare '{MARKER_ATTR}' in "
        f"the realm user profile (see README 'Realm prerequisites')."
    )


def fetch_keycloak_users(admin, page: int = 500) -> list:
    users, first = [], 0
    while True:
        batch = admin.get_users(query={"first": first, "max": page})
        users.extend(batch)
        if len(batch) < page:
            return users
        first += page


def connect_ldap(cfg: dict):
    from ldap3 import ALL, Connection, Server, Tls

    lc = cfg["ldap"]
    tls = Tls(validate=ssl.CERT_REQUIRED if lc.get("verify", True) else ssl.CERT_NONE)
    server = Server(lc["url"], use_ssl=lc["url"].lower().startswith("ldaps"), tls=tls, get_info=ALL)
    if lc["auth"]["method"] == "gssapi":
        from ldap3 import GSSAPI, SASL
        return Connection(server, authentication=SASL, sasl_mechanism=GSSAPI, auto_bind=True)
    return Connection(
        server, user=lc["auth"]["bind_dn"], password=lc["auth"]["bind_password"], auto_bind=True
    )


def fetch_ldap_users(conn, cfg: dict) -> dict:
    from ldap3 import SUBTREE

    lc, mappings = cfg["ldap"], cfg["sync"]["mappings"]
    desired = {}
    for entry in conn.extend.standard.paged_search(
        search_base=lc["search_base"],
        search_filter=lc["user_filter"],
        search_scope=SUBTREE,
        attributes=list(mappings.keys()),
        paged_size=500,
        generator=True,
    ):
        if entry.get("type") != "searchResEntry":
            continue
        attrs = entry["attributes"]
        uids = attrs.get("uid") or []
        if not uids:
            continue
        username = str(uids[0] if isinstance(uids, list) else uids)
        desired[username] = desired_user(attrs, cfg["sync"])
        desired[username]["username"] = username
    return desired


def apply(admin, plan: dict, cfg_sync: dict, dry_run: bool) -> Counter:
    counts = Counter()
    prefix = "[dry-run] " if dry_run else ""
    action = cfg_sync.get("leaver_action", "disable")

    def _do(count_key: str, verb: str, username: str, fn):
        # One bad record (e.g. a name that trips profile validation) must not abort a bulk run.
        log.info("%s%s %s", prefix, verb, username)
        if not dry_run:
            try:
                fn()
            except Exception as e:  # noqa: BLE001 - deliberately resilient
                counts["failed"] += 1
                log.error("FAILED %s %s: %s", verb, username, e)
                return
        counts[count_key] += 1

    for rep in plan["creates"]:
        _do("created", "CREATE", rep["username"], lambda rep=rep: admin.create_user(rep))
    for rep in plan["updates"]:
        _do("updated", "UPDATE", rep["username"], lambda rep=rep: admin.update_user(rep["id"], rep))
    for user in plan["leavers"]:
        if action == "delete":
            _do("removed", "DELETE", user["username"], lambda u=user: admin.delete_user(u["id"]))
        else:
            _do("removed", "DISABLE", user["username"],
                lambda u=user: admin.update_user(u["id"], {**u, "enabled": False}))
    return counts


def run(cfg: dict, dry_run: bool = False) -> int:
    dry_run = dry_run or cfg["sync"].get("dry_run", False)
    admin = connect_keycloak(cfg)
    current = fetch_keycloak_users(admin)
    ldap_conn = connect_ldap(cfg)
    desired = fetch_ldap_users(ldap_conn, cfg)

    plan = partition(desired, current, cfg["sync"])
    log.info(
        "realm=%s ldap_in_scope=%d keycloak_users=%d -> create=%d update=%d leaver=%d",
        cfg["keycloak"]["realm"], len(desired), len(current),
        len(plan["creates"]), len(plan["updates"]), len(plan["leavers"]),
    )
    counts = apply(admin, plan, cfg["sync"], dry_run)
    log.info("done: %s", dict(counts))
    return 1 if counts.get("failed") else 0


def adopt_existing(cfg: dict, dry_run: bool = False) -> int:
    """One-time: mark current realm users as managed so later syncs can govern them."""
    dry_run = dry_run or cfg["sync"].get("dry_run", False)
    admin = connect_keycloak(cfg)
    exclude = cfg["sync"].get("exclude_users", [])
    adopted = 0
    for user in fetch_keycloak_users(admin):
        if is_protected(user["username"], exclude):
            continue
        payload = adopt_payload(user)
        if payload is None:
            continue
        adopted += 1
        log.info("%sADOPT %s", "[dry-run] " if dry_run else "", user["username"])
        if not dry_run:
            admin.update_user(user["id"], payload)
    log.info("adopt done: marked %d user(s)", adopted)
    return 0
