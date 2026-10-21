# ldap-keycloak-sync

Push-based, one-way sync of user data from an LDAP directory into a Keycloak realm via the
Keycloak Admin REST API.

Keycloak's built-in LDAP federation / user import requires Keycloak to reach the LDAP server.
When LDAP sits behind a VPN that Keycloak can't reach, that doesn't work. This tool runs the
other way round: as a job wherever LDAP *is* reachable, reading LDAP and **pushing** changes
into Keycloak. Designed to run as an OpenShift `CronJob`.

## What it does

On each run it reconciles the realm against an LDAP search:

- **Create** — an LDAP user matching the configured filter who isn't in Keycloak is created
  (enabled, with mapped attributes, no credentials or roles).
- **Update** — an existing user gets only the **changed** mapped fields written back. No change
  means no API call (idempotent).
- **Disable** (default) or **delete** — a user who has fallen out of the LDAP filter scope is
  disabled. Returning to scope re-enables them.

### Safety guarantees

- **Never touches credentials or role/group mappings.** Updates only send the mapped
  `UserRepresentation` fields; credentials and role/group mappings are separate REST resources
  that are never in the payload.
- **Preserves unmanaged attributes.** Only mapped attribute keys are merged; other attributes
  on the user are left intact.
- **Only disables users it owns.** Created/updated users are tagged with a `managedByLdapSync`
  attribute. The disable/delete path only acts on tagged users, so users created out-of-band
  are never affected.
- **Protected principals.** Usernames matching `service-account-*` and any in
  `sync.exclude_users` are skipped by every path (create/update/disable/adopt).
- **Realm must exist** — a missing target realm is a fatal error, never a create.
- **Secrets never live in config files** — credentials are read from the environment
  (`${VAR}`), supplied by a Kubernetes Secret.

## Install

```bash
pip install .
# for ldap.auth.method: gssapi (needs system krb5 libs, e.g. `dnf install krb5-devel`):
pip install '.[gssapi]'
```

## Configuration

Copy [`config.example.yaml`](config.example.yaml) and edit. Key points:

- **Mappings are `ldap_attr: keycloak_target`** (source → destination). A target in
  `{username, firstName, lastName, email, emailVerified, enabled}` is a top-level field;
  anything else becomes a custom attribute. `uid: username` is the required join key.
- **`user_filter`** decides who belongs in the realm. Scope it to your authoritative group
  (e.g. `memberOf=...`). `(uid=*)` imports everyone the bind account can see — for a large
  corporate directory that means tens of thousands of users, a heavy initial import, and
  possible server-side search-size limits; scope it unless you really mean everyone.
- **`leaver_action`**: `disable` (default, reversible) or `delete` (irreversible).

### Keycloak auth (least privilege)

Create a confidential client in the target realm (e.g. `ldap-sync`) with **Service accounts
enabled**, and grant its service account only the `realm-management` roles `view-users`,
`manage-users`, and `query-users`. Put the client secret in `KEYCLOAK_CLIENT_SECRET`.

A realm admin user (`client_id: admin-cli` + `username`/`password` + `user_realm_name: master`)
also works, but is broader than needed.

## Run locally (Kerberos)

If `ldapsearch` already works on your machine (you hold a Kerberos ticket), use GSSAPI — no
bind credentials or keytab needed:

```bash
pip install -e '.[gssapi]'
# in config.yaml: ldap.auth.method: gssapi   (omit bind_dn/bind_password)
export KEYCLOAK_CLIENT_SECRET=...            # or KEYCLOAK_USERNAME / KEYCLOAK_PASSWORD
ldap-keycloak-sync --config config.yaml --dry-run
```

`--dry-run` logs the planned create/update/disable actions and makes no changes. Drop it to
apply.

## One-time migration (`--adopt-existing`)

Users that already existed before this tool was introduced don't carry the ownership marker,
so the disable path will ignore them. At cutover, tag them once:

```bash
ldap-keycloak-sync --config config.yaml --adopt-existing   # add --dry-run to preview
```

This marks current realm users (except protected ones) as managed, changing nothing else.
After that, a normal run governs them fully — updating those still in LDAP scope and disabling
those who aren't.

## Deploy on OpenShift

```bash
# 1. Build and push the image (distroless Red Hat Hardened Image runtime).
podman build -t <registry>/ldap-keycloak-sync:latest -f Containerfile .
podman push <registry>/ldap-keycloak-sync:latest

# 2. Create the Secret (do NOT commit real values).
oc create secret generic ldap-keycloak-sync \
  --from-literal=KEYCLOAK_CLIENT_SECRET=... \
  --from-literal=LDAP_BIND_DN='uid=svc-ldap-sync,ou=serviceaccounts,dc=example,dc=com' \
  --from-literal=LDAP_BIND_PASSWORD=...

# 3. Edit deploy/configmap.yaml (url/realm/search_base/user_filter) and cronjob.yaml (image),
#    then apply.
oc apply -f deploy/configmap.yaml
oc apply -f deploy/cronjob.yaml
```

The CronJob mounts the ConfigMap at `/etc/sync`, pulls secrets via `envFrom`, and runs under a
restricted-v2-compatible `securityContext` (non-root, read-only root FS, all capabilities
dropped).

**GSSAPI in-pod:** the distroless runtime has no krb5 libraries. To use `method: gssapi` in a
pod, either bundle krb5 libs into the image (copy them from the builder stage) or switch the
runtime to a UBI base, then mount a keytab Secret and a `krb5.conf`. Simple bind is the
default pod path.

## Performance & scaling

This realm is intended to hold **all company users** (tens of thousands). Measured against the
live systems:

- **LDAP** returns ~28,500 uids in <2s — negligible at any scale.
- **Keycloak REST** round-trips are ~0.12s (read) / ~0.2s (write); no rate limiting observed.

| Scope                      | Per-run list fetch | One-time initial import | Steady-state run |
|----------------------------|--------------------|-------------------------|------------------|
| ~1,000                     | ~0.3s              | ~3.5 min                | seconds          |
| ~28,500 (whole company)    | ~9s                | **~95 min (≈1.5 h)**    | ~10–20s          |

The sync is **sequential and idempotent** by design: each run writes only the users that
actually changed, so steady-state runs stay cheap (~10–20s) even at full-company scale, and an
interrupted run self-heals — the next run skips already-synced users and continues. No
parallelization or resumability code is needed; the bottleneck is one-time, not recurring.

At whole-company scale the job holds both user sets in memory (a few hundred MB); the CronJob
requests a correspondingly higher memory limit.

### Initial import

The first run creates every in-scope user and takes ~1.5 h at whole-company scale. The default
CronJob `activeDeadlineSeconds: 600` (10 min) would kill it mid-run. For the initial import,
either:

- **Run it once manually** (recommended) — locally or via `oc run` — then let the CronJob take
  over steady-state:
  ```bash
  ldap-keycloak-sync --config config.yaml        # add --dry-run first to preview
  ```
- or **temporarily raise `activeDeadlineSeconds`** in `deploy/cronjob.yaml` for the first run,
  then revert it.

Because the sync is idempotent, even an interrupted import completes over successive cron runs
(`concurrencyPolicy: Forbid` prevents overlap).

## Development

```bash
pip install -e '.[dev]'
pytest                # or: python tests/test_sync.py
```

The reconcile logic (`desired_user`, `diff_update`, `partition`, `adopt_payload`,
`is_protected` in `ldap_keycloak_sync/sync.py`) is pure and unit-tested without a network.

## Not yet supported

- `memberOf` sync (the realm user-profile caps it at 2048 chars; needs group filtering first).
- Creating users with local credentials (brokered-IdP users have none).

## License

MIT — see [LICENSE](LICENSE).
