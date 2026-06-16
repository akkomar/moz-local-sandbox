# moz-local-sandbox: Mozilla DE additions

This branch (`mozdata`, off the `padenot/moz-local-sandbox` upstream)
adds the bits that make `ccode-macos` usable for Mozilla Data
Engineering work: GCP/BigQuery access, Atlassian + DataHub network
reach, JVM/Maven for Beam-style ETL jobs, and a handful of toolchain
redirects.

Lives in the repo dir for proximity to the launcher; not part of the
upstream contribution. Move it out if these notes ever stop being
useful for managing the `mozdata` branch.

## Modifications vs `padenot/moz-local-sandbox`

### New launcher env vars

| Var | Effect |
|---|---|
| `CCODE_RO_EXTRA=path[:path...]` | Mount additional absolute paths read-only. Lets one project be exposed rw while a sibling tree stays reachable RO for cross-repo greps. |
| `CCODE_RW_EXTRA=path[:path...]` | Same shape, but read-write. For sessions that need to edit files across multiple repos. |
| `CCODE_GH_TOKEN=<token>` | Forward a fine-grained GitHub PAT instead of relying on `gh auth token` (which on the host can mint a full-access OAuth token from the keychain). |
| `CCODE_GCP_IMPERSONATE=<sa-email>` | Run a host-side GCE metadata-server emulator that mints impersonated SA tokens via your host ADC. No key at rest. |
| `CCODE_GCP_PROJECT=<id>` | Override the project parsed from the SA email (used only when the billing/job-execution project differs from the SA's home project). |

### Toolchain redirects

The sandbox blocks writes to most of `~/.cache/`, `~/.local/share/`,
and macOS `~/Library/Caches/`. Without redirects, common tools fail
with "operation not permitted". Each redirect points the affected tool
at `~/.sandbox/<tool>/` instead.

- `XDG_CACHE_HOME` redirected so XDG-honoring tools (`pre-commit`, `gh`, ...) keep working without hitting the blocked `~/.cache/`.
- `XDG_DATA_HOME` redirected so `uv` / `uvx` can write downloaded Python interpreters and tool envs.
- `GOCACHE` redirected explicitly: macOS Go ignores `XDG_CACHE_HOME` and would otherwise hit the blocked `~/Library/Caches/go-build/`.
- `MAVEN_OPTS=-Dmaven.repo.local=...` points Maven at a sandbox-private local repository; a generated `settings.xml` routes Maven Resolver through the netproxy; `-Dhttps.proxyHost=...` system properties get added for plugins (Spotless, etc.) that bypass the Resolver.
- `JAVA_HOME` set to SDKMAN's `candidates/java/current` so `mvn`, `javac`, and other JDK tools find a workable JDK.

### Sandbox profile additions

- `~/.config/gcx` exposed RO (Mozilla-internal CLI).
- `~/.config/gcloud/virtenv` exposed RO when `CCODE_GCP_IMPERSONATE` is active (Homebrew gcloud wrapper sources the activate script from there; parent `~/.config/gcloud/` is intentionally NOT exposed because it holds the host user's ADC and `credentials.db`).

### Network policy

`policies/anthropic-mozilla.json` extends `anthropic-only` with the
hosts a DE session typically needs:

- Mozilla services (Phabricator, Bugzilla, BMO API, telemetry stack)
- GitHub + npm + crates.io + PyPI (host package fetching)
- Atlassian (`mozilla-hub.atlassian.net` for Jira / Confluence MCP)
- Acryl DataHub (`mozilla.acryl.io` metadata catalog)
- `*.googleapis.com` (BigQuery, IAM credentials, OAuth)

## Usage

### Baseline (no GCP)

```sh
CCODE_CWD_ONLY=1 \
CCODE_RO_EXTRA=~/mozilla \
CCODE_NETPOLICY=anthropic-mozilla \
CCODE_GH_TOKEN=$(op read 'op://Employee/<github-pat-item>/credential') \
  ~/mozilla/dev/moz-local-sandbox/ccode-macos
```

What each var does:

- `CCODE_CWD_ONLY=1`: restrict rw to the current directory rather than the whole `$CCODE_SRC` tree.
- `CCODE_RO_EXTRA=~/mozilla`: re-expose the rest of `~/mozilla` read-only so cross-repo greps still work.
- `CCODE_NETPOLICY=anthropic-mozilla`: start netproxy with the Mozilla allowlist policy. Sandbox is locked to loopback; the proxy filters by hostname.
- `CCODE_GH_TOKEN=...`: forward a scoped GitHub PAT instead of the host keychain token.

### With GCP (impersonation)

```sh
CCODE_CWD_ONLY=1 \
CCODE_RO_EXTRA=~/mozilla \
CCODE_NETPOLICY=anthropic-mozilla \
CCODE_GH_TOKEN=$(op read 'op://Employee/<github-pat-item>/credential') \
CCODE_GCP_IMPERSONATE=bq-dev-sandbox@moz-fx-data-proto.iam.gserviceaccount.com \
  ~/mozilla/dev/moz-local-sandbox/ccode-macos
```

The launcher spawns `bin/ccode-gcp-metadata` on the host, a loopback
HTTP server that emulates the GCE metadata API. On each token refresh
it shells out to `gcloud auth print-access-token
--impersonate-service-account=<sa>`, which uses your host ADC to call
`iamcredentials.generateAccessToken` outside the sandbox. Inside the
sandbox, `GCE_METADATA_HOST` + `GCE_METADATA_ROOT` steer gcloud / bq /
Python `google-auth` / Go `oauth2/google` to the loopback server;
tokens auto-refresh inside the 1h lifetime.

Project served from `/project/project-id` (and exported as
`GOOGLE_CLOUD_PROJECT` / `CLOUDSDK_CORE_PROJECT`) is parsed from the
SA email by default. Set `CCODE_GCP_PROJECT` to override when the
billing/job-execution project differs from the SA's home project.

Prerequisites:

- Host user holds `roles/iam.serviceAccountTokenCreator` on the SA.
  For `bq-dev-sandbox`, the platform_workgroup gets this binding via
  dataservices-infra (see DENG-10793 / DENG-11241).
- Host `gcloud` is logged in (user ADC). The launcher runs a preflight
  `gcloud auth print-access-token` and bails before starting the
  sandbox if impersonation fails.

Why not just `gcloud config set auth/impersonate_service_account`
inside the sandbox: that flow needs your *user* ADC as the source
identity, and your user identity has far more reach than any scoped
SA (including the prod BQ write you'd otherwise be firewalling
against). So the impersonation happens outside the sandbox; only the
result enters.

No fallback for OIDC identity tokens: the metadata server returns 404
on the `/identity` endpoint. If a tool needs identity tokens (IAP-
fronted services, Cloud Run with auth, custom JWT signing), wiring
that up means adding an `iamcredentials.generateIdToken` call to
`gcp-metadata/server.go`. Not implemented today.

### Verify in-sandbox

```sh
gcloud auth list                                                  # SA shown as ACTIVE
gcloud auth print-access-token                                    # real ya29.… minted via the metadata server
gcloud config get-value project                                   # the active project
bq query --use_legacy_sql=false 'SELECT SESSION_USER() AS who'    # confirms BQ executes AS the SA
```

`gcloud` errors are usually more readable than the equivalent
failures from the GCP client libraries; when something looks wrong
from Python, retry the same call via `bq`/`gcloud` for a clearer
message.

`~/.sandbox/gcp-metadata.log` records per-request `ALLOW`/`MISS`/`DENY`
lines plus token-refresh markers; it's the first place to look when
asking "is gcloud actually reaching the metadata server?"

## Implementation notes: gcloud + metadata-server quirks

Non-obvious things found while wiring up `CCODE_GCP_IMPERSONATE`,
recorded so future debugging doesn't re-derive them:

- **`GCE_METADATA_HOST` alone is not enough.** gcloud's
  GCE-detection / token-refresh path (`gce_read.py`) reads only
  `GCE_METADATA_ROOT`; `GCE_METADATA_HOST` is the env var the Python
  google-auth library reads. The launcher sets both.
- **gcloud's "am I on GCE?" check is `body.isdigit()` on
  `/project/numeric-project-id`.** Returning 404 keeps gcloud in
  credentials.db mode and breaks impersonation; the server returns
  `"0"` (a placeholder digit) so the check passes.
- **`?recursive=true` must return JSON, not text.** google-auth calls
  `service-accounts/<email>/?recursive=true` and parses the body as a
  dict (`info["email"]`). Returning the plain-text directory listing
  surfaces as `TypeError: string indices must be integers` from inside
  `gcloud auth print-access-token`.
- **404 vs 501 on `/identity` matters.** ID-token issuance isn't
  implemented, but returning 501 gets surfaced as a fatal
  `MetadataServerException` that breaks unrelated `print-access-token`
  calls. The server returns 404 instead, which gcloud handles cleanly.
- **`active_config` must have no trailing newline.** gcloud reads the
  file content verbatim and treats `default\n` as a different config
  name than `default`, then misses `configurations/config_default`.
  The launcher uses `printf 'default' > ...`.
- **`CLOUDSDK_CONFIG` is wiped per launch.** The launcher points
  gcloud at `$SBX/gcloud-impersonate/` and deletes it on each start.
  Stale active-account / cached-token state otherwise shadows the
  metadata server and gcloud keeps using a prior session's SA. (Hit
  this when switching between two SAs after both had run in the same
  `~/.sandbox/`.)

## Known limitations

### macOS `~/Library/Caches/` paths

Python tools that resolve their cache dir via `platformdirs` /
`appdirs` get `~/Library/Caches/<app>` on macOS and **ignore**
`XDG_CACHE_HOME`. The sandbox blocks `~/Library/Caches/` so those
tools fail with `PermissionError: ... could not be created`.

Hit in: `glean_parser` tests that exercise
`validate_ping.validate_ping(...)` (uses `diskcache` writing to
`~/Library/Caches/glean_parser`).

No general launcher fix yet (would need to open up `~/Library/Caches/`
RW with the same contamination concern we deliberately avoided for
`~/.cache/`). Per-tool workarounds: check if the tool has a custom
cache-dir env var or CLI flag. For glean_parser specifically, just
skip the affected tests in-sandbox.
