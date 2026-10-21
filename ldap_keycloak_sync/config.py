"""Load, env-expand and validate the YAML config."""

from __future__ import annotations

import os
import re

import yaml

_ENV_RE = re.compile(r"\$\{(\w+)\}")


def _expand(value):
    """Recursively replace ${VAR} in strings with os.environ[VAR].

    Raises KeyError with a clear message if a referenced variable is unset, so a
    missing secret fails loudly instead of leaking a literal '${VAR}' into a bind.
    """
    if isinstance(value, str):
        def sub(m):
            name = m.group(1)
            try:
                return os.environ[name]
            except KeyError:
                raise KeyError(f"config references unset environment variable ${{{name}}}")
        return _ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _require(cfg: dict, path: str):
    node = cfg
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node or node[part] in (None, ""):
            raise ValueError(f"config: missing required key '{path}'")
        node = node[part]
    return node


def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = _expand(yaml.safe_load(f) or {})

    _require(cfg, "keycloak.url")
    _require(cfg, "keycloak.realm")
    kc = cfg["keycloak"]
    if not (kc.get("client_secret") or (kc.get("username") and kc.get("password"))):
        raise ValueError("config: keycloak needs client_id+client_secret OR username+password")

    _require(cfg, "ldap.url")
    _require(cfg, "ldap.search_base")
    _require(cfg, "ldap.user_filter")
    method = cfg["ldap"].setdefault("auth", {}).get("method", "simple")
    if method not in ("simple", "gssapi"):
        raise ValueError("config: ldap.auth.method must be 'simple' or 'gssapi'")
    if method == "simple":
        _require(cfg, "ldap.auth.bind_dn")
        _require(cfg, "ldap.auth.bind_password")

    mappings = _require(cfg, "sync.mappings")
    if "uid" not in mappings or mappings["uid"] != "username":
        raise ValueError("config: sync.mappings must include 'uid: username' (the join key)")
    if cfg["sync"].get("leaver_action", "disable") not in ("disable", "delete"):
        raise ValueError("config: sync.leaver_action must be 'disable' or 'delete'")

    # defaults
    cfg["keycloak"].setdefault("verify", True)
    cfg["ldap"].setdefault("verify", True)
    cfg["sync"].setdefault("email_verified", True)
    cfg["sync"].setdefault("exclude_users", [])
    cfg["sync"].setdefault("leaver_action", "disable")
    cfg["sync"].setdefault("dry_run", False)
    return cfg
