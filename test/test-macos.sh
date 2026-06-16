#!/bin/bash
#
# test-macos.sh — sandbox profile + script tests for ccode-macos.
#
# Two layers of tests:
#   1. Profile semantics: take the exact profile ccode-macos would use
#      (via `ccode-macos --print-profile`) and probe it with sandbox-exec
#      against a series of read/write/exec scenarios.
#   2. Script env handling: invoke ccode-macos with a stub `claude` binary
#      that prints its environment, and verify env -i drops host secrets
#      while forwarding the expected toolchain redirects.
#
# No real claude install is required to run these tests.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/ccode-macos"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "test-macos.sh: skipped (not macOS)" >&2
    exit 0
fi
if [[ ! -x "$SCRIPT" ]]; then
    echo "FATAL: $SCRIPT not executable" >&2
    exit 2
fi

TMP=$(mktemp -d -t ccode-test)
trap 'rm -rf "$TMP"' EXIT

TEST_RW="$TMP/rw-root"
mkdir -p "$TEST_RW"

PASS=0
FAIL=0
ok()   { echo "  ok    $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1${2+ -- $2}" >&2; FAIL=$((FAIL+1)); }

# expect <desc> <ok|deny> <command...>
# Runs the command and asserts exit-zero (ok) or non-zero (deny).
expect() {
    local desc="$1" expected="$2"; shift 2
    local out exit
    out=$("$@" 2>&1); exit=$?
    case "$expected" in
        ok)   if [[ $exit -eq 0 ]]; then ok "$desc"; else fail "$desc" "exit=$exit out=$(printf %q "$out")"; fi ;;
        deny) if [[ $exit -ne 0 ]]; then ok "$desc (denied)"; else fail "$desc" "expected deny but exit=0"; fi ;;
        *) fail "$desc" "bad expectation: $expected" ;;
    esac
}

# Generate the profile that ccode-macos would use, with a test RW root.
PROFILE_FILE="$TMP/profile.sb"
CCODE_SRC="$TEST_RW" "$SCRIPT" --print-profile > "$PROFILE_FILE" \
    || { echo "FATAL: failed to generate profile"; exit 2; }

run_sb() { sandbox-exec -f "$PROFILE_FILE" "$@"; }

echo "==== profile: positive (should succeed) ===="
expect "exec /usr/bin/true"          ok run_sb /usr/bin/true
expect "read /etc/hosts"             ok run_sb /bin/cat /etc/hosts
expect "list /usr/bin"               ok run_sb /bin/ls /usr/bin
expect "stat \$HOME"                 ok run_sb /bin/test -d "$HOME"
expect "read \$HOME/.gitconfig"      ok run_sb /bin/cat "$HOME/.gitconfig"
expect "write to RW_ROOT"            ok run_sb /bin/sh -c "echo x > $TEST_RW/probe"
expect "RW_ROOT write took effect"   ok run_sb /usr/bin/grep -q '^x$' "$TEST_RW/probe"
expect "write to /tmp"               ok run_sb /bin/sh -c "echo x > /tmp/ccode-test-tmp && rm /tmp/ccode-test-tmp"
expect "write to ~/.claude (shared with host)" ok run_sb /bin/sh -c "mkdir -p '$HOME/.claude' && touch '$HOME/.claude/.ccode-test-probe' && rm '$HOME/.claude/.ccode-test-probe'"

echo
echo "==== profile: negative (should be denied) ===="
expect "deny write to \$HOME root"   deny run_sb /bin/sh -c "echo bad > $HOME/.ccode-test-bad-DELETE-ME"
expect "deny write to ~/.gitconfig"  deny run_sb /bin/sh -c "echo bad >> $HOME/.gitconfig"
expect "deny write to /etc"          deny run_sb /bin/sh -c "echo bad > /etc/ccode-test-bad"
expect "deny write to /usr/bin"      deny run_sb /bin/sh -c "echo bad > /usr/bin/ccode-test-bad"
# Ensure ssh private keys cannot be read. If no key exists yet, sandbox-exec
# still denies the open before ENOENT is reached, so this remains a useful
# probe regardless.
expect "deny read of ~/.ssh/id_rsa"      deny run_sb /bin/cat "$HOME/.ssh/id_rsa"
expect "deny read of ~/.ssh/id_ed25519"  deny run_sb /bin/cat "$HOME/.ssh/id_ed25519"
expect "deny ls of ~/Documents"      deny run_sb /bin/ls "$HOME/Documents"
# ~/Library/Keychains is intentionally rw — Claude Code on macOS stores
# its OAuth token there and rewrites it on /login (token refresh).
# Per-entry access is still gated by securityd ACLs (consent prompt for
# unrelated entries), but the file-level access has to be allowed.
expect "read ~/Library/Keychains (claude OAuth needs RW)" ok run_sb /bin/test -r "$HOME/Library/Keychains"
# Pasteboard mach service denied — pbcopy should fail to talk to it.
# (AppleEvents is *not* tested here: on modern macOS, cross-app scripting
# is gated by TCC/entitlements rather than mach-lookup, so a sandbox-exec
# deny does not reliably block `osascript -e 'tell app …'`. The deny rule
# is kept in the profile as an extra layer but cannot be asserted on.)
expect "deny pbcopy (clipboard)"     deny run_sb /bin/sh -c "echo test | /usr/bin/pbcopy"
# Belt-and-braces cleanup in case any of the above accidentally created files.
rm -f "$HOME/.ccode-test-bad-DELETE-ME" "$HOME/.claude/.ccode-test-bad-DELETE-ME" 2>/dev/null

echo
echo "==== profile: CCODE_RW_EXTRA (additional writable trees) ===="
TEST_RW_EXTRA_A="$TMP/rw-extra-a"
TEST_RW_EXTRA_B="$TMP/rw-extra-b"
mkdir -p "$TEST_RW_EXTRA_A" "$TEST_RW_EXTRA_B"
PROFILE_FILE_RW="$TMP/profile-rw-extra.sb"
CCODE_SRC="$TEST_RW" CCODE_RW_EXTRA="$TEST_RW_EXTRA_A:$TEST_RW_EXTRA_B" \
    "$SCRIPT" --print-profile > "$PROFILE_FILE_RW" \
    || { echo "FATAL: failed to generate CCODE_RW_EXTRA profile"; exit 2; }
run_sb_rw() { sandbox-exec -f "$PROFILE_FILE_RW" "$@"; }
expect "write to first CCODE_RW_EXTRA path"  ok run_sb_rw /bin/sh -c "echo a > $TEST_RW_EXTRA_A/probe"
expect "write to second CCODE_RW_EXTRA path" ok run_sb_rw /bin/sh -c "echo b > $TEST_RW_EXTRA_B/probe"
expect "primary RW_ROOT still writable"      ok run_sb_rw /bin/sh -c "echo c > $TEST_RW/probe-rw-extra"
if grep -q "CCODE_RW_EXTRA: $TEST_RW_EXTRA_A" "$PROFILE_FILE_RW" && \
   grep -q "CCODE_RW_EXTRA: $TEST_RW_EXTRA_B" "$PROFILE_FILE_RW"; then
    ok "both CCODE_RW_EXTRA entries appear as labelled subpaths"
else
    fail "both CCODE_RW_EXTRA entries appear as labelled subpaths" "missing marker comment(s) in profile"
fi
# Rejects an unset/missing path before the profile is generated.
if CCODE_SRC="$TEST_RW" CCODE_RW_EXTRA="$TMP/does-not-exist" "$SCRIPT" --print-profile >/dev/null 2>&1; then
    fail "CCODE_RW_EXTRA rejects nonexistent paths" "script accepted a missing path"
else
    ok "CCODE_RW_EXTRA rejects nonexistent paths"
fi
# Rejects a relative path.
if CCODE_SRC="$TEST_RW" CCODE_RW_EXTRA="relative/path" "$SCRIPT" --print-profile >/dev/null 2>&1; then
    fail "CCODE_RW_EXTRA rejects relative paths" "script accepted a relative path"
else
    ok "CCODE_RW_EXTRA rejects relative paths"
fi

echo
echo "==== script: env handling (env -i + redirects) ===="
mkdir -p "$TMP/stub-bin"
cat > "$TMP/stub-bin/claude" <<'STUB'
#!/bin/bash
# Test stub: print the env it received, ignoring real claude args.
env
STUB
chmod +x "$TMP/stub-bin/claude"

# Set a host-only env var that must NOT cross env -i, plus a tame value
# to confirm forwarding works for variables the script does export.
export CCODE_TEST_HOST_SECRET="must-not-leak"
output=$(PATH="$TMP/stub-bin:$PATH" CCODE_SRC="$TEST_RW" "$SCRIPT" 2>&1)

check() {
    local desc="$1" pattern="$2" mode="$3"
    if grep -qE "$pattern" <<<"$output"; then
        case "$mode" in
            present) ok "$desc" ;;
            absent)  fail "$desc" "pattern '$pattern' was present" ;;
        esac
    else
        case "$mode" in
            present) fail "$desc" "pattern '$pattern' missing from env output" ;;
            absent)  ok "$desc" ;;
        esac
    fi
}

check "CARGO_HOME redirected to ~/.sandbox/cargo" '^CARGO_HOME=.*\.sandbox/cargo$'  present
check "UV_CACHE_DIR redirected"                   '^UV_CACHE_DIR=.*\.sandbox/uv$'   present
check "GOPATH redirected"                         '^GOPATH=.*\.sandbox/go$'         present
check "GOMODCACHE redirected"                     '^GOMODCACHE=.*\.sandbox/go/pkg/mod$' present
check "NPM_CONFIG_CACHE redirected"               '^NPM_CONFIG_CACHE=.*\.sandbox/npm$'  present
check "NPM_CONFIG_PREFIX redirected"              '^NPM_CONFIG_PREFIX=.*\.sandbox/npm-prefix$' present
check "PIP_CACHE_DIR redirected"                  '^PIP_CACHE_DIR=.*\.sandbox/pip$' present
check "RUSTUP_HOME points at host (read-only)"    '^RUSTUP_HOME=.*/\.rustup$'       present
check "git core.hooksPath override set"           '^GIT_CONFIG_KEY_0=core\.hooksPath$' present
check "git hooks redirected to empty dir"         '^GIT_CONFIG_VALUE_0=.*\.sandbox/empty-hooks$' present
check "HOME forwarded"                            '^HOME='                          present
check "host secret blocked by env -i"             '^CCODE_TEST_HOST_SECRET='        absent

# CLAUDE_CODE_OAUTH_TOKEN must NOT be forwarded: the sandbox shares the
# host keychain rw, and an env-var token alongside the keychain-managed
# key triggers a "Auth conflict" warning in Claude Code.
if grep -q '^CLAUDE_CODE_OAUTH_TOKEN=' <<<"$output"; then
    fail "CLAUDE_CODE_OAUTH_TOKEN not forwarded" "env var was set, conflicts with keychain"
else
    ok "CLAUDE_CODE_OAUTH_TOKEN not forwarded (keychain is sole source of truth)"
fi

echo
echo "==== noexec: opt-in via CCODE_NOEXEC=1 ===="
# Stub claude that writes a fresh executable file inside RW_ROOT and exits.
# After ccode-macos returns, the file should still exist but its +x bit
# must be stripped.
mkdir -p "$TMP/noexec-stub"
cat > "$TMP/noexec-stub/claude" <<STUB
#!/bin/bash
# Write a script with +x to the workdir. The ccode-macos EXIT trap should
# strip the +x bit when CCODE_NOEXEC=1.
printf '%s\n' '#!/bin/bash' 'echo evil' > '$TEST_RW/sandbox-built-binary'
chmod +x '$TEST_RW/sandbox-built-binary'
STUB
chmod +x "$TMP/noexec-stub/claude"

PATH="$TMP/noexec-stub:$PATH" CCODE_SRC="$TEST_RW" CCODE_NOEXEC=1 "$SCRIPT" >/dev/null 2>&1 || true

if [[ -f "$TEST_RW/sandbox-built-binary" ]]; then
    ok "sandbox-built file persists after exit"
    if [[ -x "$TEST_RW/sandbox-built-binary" ]]; then
        fail "noexec stripped +x from new sandbox-built file" "+x still set"
    else
        ok "noexec stripped +x from new sandbox-built file"
    fi
else
    fail "sandbox-built file persists after exit" "file missing — stub did not run"
fi

# Counter-test: when CCODE_NOEXEC is unset, the +x bit is preserved.
rm -f "$TEST_RW/sandbox-built-binary"
PATH="$TMP/noexec-stub:$PATH" CCODE_SRC="$TEST_RW" "$SCRIPT" >/dev/null 2>&1 || true
if [[ -x "$TEST_RW/sandbox-built-binary" ]]; then
    ok "without CCODE_NOEXEC, +x is preserved"
else
    fail "without CCODE_NOEXEC, +x is preserved" "+x stripped even without opt-in"
fi
rm -f "$TEST_RW/sandbox-built-binary"

echo
echo "==== network policy: profile shape ===="
# With a policy, the profile network section must switch to deny + only
# loopback proxy ports. Use --print-profile (sentinel ports, no proxy
# actually started).
prof_with=$(CCODE_NETPOLICY=anthropic-only CCODE_SRC="$TEST_RW" "$SCRIPT" --print-profile 2>&1)
if grep -q '(deny network\*)' <<<"$prof_with" && \
   grep -q 'localhost:<HTTP_PORT>' <<<"$prof_with" && \
   grep -q 'localhost:<SOCKS_PORT>' <<<"$prof_with"; then
    ok "policy active: profile denies network, allows proxy ports only"
else
    fail "policy active: profile denies network, allows proxy ports only" "got profile not as expected"
fi

prof_without=$(CCODE_SRC="$TEST_RW" "$SCRIPT" --print-profile 2>&1)
if grep -q '(allow network\*)' <<<"$prof_without"; then
    ok "policy unset: profile allows network (default behaviour)"
else
    fail "policy unset: profile allows network (default behaviour)" "expected (allow network*)"
fi

# Unknown policy name should bail with a clear error, not silently fall
# back to open network.
out_bad=$(CCODE_NETPOLICY=this-does-not-exist CCODE_SRC="$TEST_RW" "$SCRIPT" --print-profile 2>&1 || true)
if grep -q 'policy not found' <<<"$out_bad"; then
    ok "unknown policy name aborts loudly"
else
    fail "unknown policy name aborts loudly" "got: $out_bad"
fi

echo
echo "==== network policy: env wiring when proxy is active ===="
output_with=$(PATH="$TMP/stub-bin:$PATH" CCODE_SRC="$TEST_RW" CCODE_NETPOLICY=anthropic-only "$SCRIPT" 2>/dev/null || true)
check_proxy() {
    local desc="$1" pattern="$2"
    if grep -qE "$pattern" <<<"$output_with"; then ok "$desc"
    else fail "$desc" "pattern '$pattern' missing from env"; fi
}
check_proxy "HTTP_PROXY -> loopback netproxy"  '^HTTP_PROXY=http://127\.0\.0\.1:[0-9]+$'
check_proxy "HTTPS_PROXY -> loopback netproxy" '^HTTPS_PROXY=http://127\.0\.0\.1:[0-9]+$'
check_proxy "ALL_PROXY uses socks5h"           '^ALL_PROXY=socks5h://127\.0\.0\.1:[0-9]+$'
check_proxy "NO_PROXY excludes loopback"       '^NO_PROXY=localhost,127\.0\.0\.1,::1$'

output_without=$(PATH="$TMP/stub-bin:$PATH" CCODE_SRC="$TEST_RW" "$SCRIPT" 2>/dev/null || true)
if grep -q '^HTTP_PROXY=' <<<"$output_without"; then
    fail "policy unset: HTTP_PROXY not set" "HTTP_PROXY leaked into env"
else
    ok "policy unset: HTTP_PROXY not set"
fi

# Proxy should be killed by the script's EXIT trap. Check directly.
sleep 0.5
if pgrep -fl ccode-netproxy >/dev/null 2>&1; then
    fail "netproxy cleaned up on exit" "stray ccode-netproxy still running: $(pgrep -fl ccode-netproxy)"
else
    ok "netproxy cleaned up on exit (no stray processes)"
fi

echo
echo "==== CCODE_GCP_IMPERSONATE: metadata-server emulator ===="
# Stub gcloud + a stub claude that probes the metadata server from inside
# the sandbox. The stub gcloud just returns a fixed token, so we can
# assert the launcher wires up env vars and the loopback server end-to-end
# without any real GCP credentials.
TEST_SA="ccode-test-sa@ccode-test-project.iam.gserviceaccount.com"
TEST_TOKEN="ya29.ccode-stub-token-marker"
TEST_PROJECT="ccode-test-project"

mkdir -p "$TMP/gcp-stub-bin"
cat > "$TMP/gcp-stub-bin/gcloud" <<STUB
#!/bin/bash
# Stub gcloud: handles only the calls ccode-macos / ccode-gcp-metadata make.
# print-access-token: print a fixed token to stdout.
case "\$*" in
    *"auth print-access-token"*)
        echo "$TEST_TOKEN"
        exit 0
        ;;
esac
echo "stub gcloud: unsupported invocation: \$*" >&2
exit 2
STUB
chmod +x "$TMP/gcp-stub-bin/gcloud"

cat > "$TMP/gcp-stub-bin/claude" <<'STUB'
#!/bin/bash
# Stub claude for the impersonate tests: print env, then curl the
# metadata server's token endpoint from inside the sandbox. Wrap the curl
# output in markers so the outer test can grep for it.
env
if [[ -n "${GCE_METADATA_HOST:-}" ]]; then
    echo "---TOKEN-PROBE-START---"
    /usr/bin/curl -s --max-time 5 \
        -H "Metadata-Flavor: Google" \
        "http://$GCE_METADATA_HOST/computeMetadata/v1/instance/service-accounts/default/token" \
        || echo "curl-failed-exit-$?"
    echo
    echo "---TOKEN-PROBE-END---"
fi
STUB
chmod +x "$TMP/gcp-stub-bin/claude"

# Happy path: launcher starts the metadata server, env vars are exported,
# token endpoint serves the stubbed token through loopback.
gcp_out=$(PATH="$TMP/gcp-stub-bin:$PATH" CCODE_SRC="$TEST_RW" \
          CCODE_GCP_IMPERSONATE="$TEST_SA" "$SCRIPT" 2>&1 || true)

check_gcp() {
    local desc="$1" pattern="$2"
    if grep -qE "$pattern" <<<"$gcp_out"; then ok "$desc"
    else fail "$desc" "pattern '$pattern' missing from output"; fi
}
check_gcp "GCE_METADATA_HOST -> loopback" '^GCE_METADATA_HOST=127\.0\.0\.1:[0-9]+$'
check_gcp "GCE_METADATA_IP -> loopback"   '^GCE_METADATA_IP=127\.0\.0\.1:[0-9]+$'
check_gcp "GOOGLE_CLOUD_PROJECT derived from SA email" "^GOOGLE_CLOUD_PROJECT=$TEST_PROJECT$"
check_gcp "CLOUDSDK_CORE_PROJECT set"                  "^CLOUDSDK_CORE_PROJECT=$TEST_PROJECT$"
check_gcp "token endpoint returns stub token"          "\"access_token\":\"$TEST_TOKEN\""
check_gcp "launcher logs server startup"               'gcp-metadata started \(sa='

# Cleanup check: scope the pgrep to this test's SA email so it doesn't
# false-positive on unrelated ccode-gcp-metadata processes the user may
# have running for real sessions.
sleep 0.5
if pgrep -fl "ccode-gcp-metadata.*$TEST_SA" >/dev/null 2>&1; then
    fail "gcp-metadata cleaned up on exit" "stray process: $(pgrep -fl ccode-gcp-metadata.*$TEST_SA)"
else
    ok "gcp-metadata cleaned up on exit (no stray processes)"
fi

# CCODE_GCP_PROJECT override: when set, served verbatim instead of
# parsing the SA email. Check the launcher's startup log on stderr —
# it includes `project=...` and is visible without needing sandbox-exec
# to actually run claude.
gcp_out_override=$(PATH="$TMP/gcp-stub-bin:$PATH" CCODE_SRC="$TEST_RW" \
                   CCODE_GCP_IMPERSONATE="$TEST_SA" \
                   CCODE_GCP_PROJECT="other-project" "$SCRIPT" 2>&1 || true)
if grep -qE 'gcp-metadata started .*project=other-project' <<<"$gcp_out_override"; then
    ok "CCODE_GCP_PROJECT overrides derived project"
else
    fail "CCODE_GCP_PROJECT overrides derived project" \
         "got: $(grep 'gcp-metadata started' <<<"$gcp_out_override" || echo '<no startup log>')"
fi

# Same for the default-derivation path: the launcher log shows the SA
# email's project segment was extracted correctly. This validates the
# project-derivation code without depending on sandbox-exec.
if grep -qE "gcp-metadata started .*project=$TEST_PROJECT" <<<"$gcp_out"; then
    ok "project derived from SA email (visible in launcher log)"
else
    fail "project derived from SA email (visible in launcher log)" \
         "got: $(grep 'gcp-metadata started' <<<"$gcp_out" || echo '<no startup log>')"
fi

# Malformed SA email rejected.
out_bad_email=$(PATH="$TMP/gcp-stub-bin:$PATH" CCODE_SRC="$TEST_RW" \
                CCODE_GCP_IMPERSONATE="not-an-sa-email" "$SCRIPT" 2>&1 || true)
if grep -q 'must be an SA email' <<<"$out_bad_email"; then
    ok "rejects malformed CCODE_GCP_IMPERSONATE value"
else
    fail "rejects malformed CCODE_GCP_IMPERSONATE value" "got: $out_bad_email"
fi

# Direct binary test: spawn ccode-gcp-metadata against the stub gcloud,
# probe the loopback HTTP endpoint, then tear it down. Verifies the
# token-refresh shell-out path works end-to-end with no sandbox-exec
# involvement — complements the in-process unit tests.
GCP_BIN="$REPO/bin/ccode-gcp-metadata"
if [[ -x "$GCP_BIN" ]]; then
    GCP_STATUS_FILE="$TMP/gcp-direct-status"
    GCP_LOG_FILE="$TMP/gcp-direct.log"
    PATH="$TMP/gcp-stub-bin:$PATH" "$GCP_BIN" \
        --sa "$TEST_SA" --project "$TEST_PROJECT" \
        > "$GCP_STATUS_FILE" 2> "$GCP_LOG_FILE" &
    GCP_DIRECT_PID=$!
    # Wait briefly for the PORT= line to appear.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [[ -s "$GCP_STATUS_FILE" ]] && grep -q '^PORT=' "$GCP_STATUS_FILE"; then break; fi
        sleep 0.1
    done
    direct_line=$(head -n1 "$GCP_STATUS_FILE")
    if [[ "$direct_line" =~ PORT=([0-9]+) ]]; then
        DIRECT_PORT="${BASH_REMATCH[1]}"
        # Token endpoint
        body=$(/usr/bin/curl -s --max-time 5 \
            -H "Metadata-Flavor: Google" \
            "http://127.0.0.1:$DIRECT_PORT/computeMetadata/v1/instance/service-accounts/default/token" || true)
        if grep -q "\"access_token\":\"$TEST_TOKEN\"" <<<"$body"; then
            ok "direct probe: token endpoint returns stub token through loopback"
        else
            fail "direct probe: token endpoint returns stub token through loopback" "body=$body"
        fi
        # Email endpoint
        email_body=$(/usr/bin/curl -s --max-time 5 \
            -H "Metadata-Flavor: Google" \
            "http://127.0.0.1:$DIRECT_PORT/computeMetadata/v1/instance/service-accounts/default/email" || true)
        if [[ "$email_body" == "$TEST_SA" ]]; then
            ok "direct probe: email endpoint returns the configured SA"
        else
            fail "direct probe: email endpoint returns the configured SA" "got: $email_body"
        fi
        # Project-id endpoint
        proj_body=$(/usr/bin/curl -s --max-time 5 \
            -H "Metadata-Flavor: Google" \
            "http://127.0.0.1:$DIRECT_PORT/computeMetadata/v1/project/project-id" || true)
        if [[ "$proj_body" == "$TEST_PROJECT" ]]; then
            ok "direct probe: project-id endpoint returns the configured project"
        else
            fail "direct probe: project-id endpoint returns the configured project" "got: $proj_body"
        fi
        # SSRF defence: request without Metadata-Flavor header is rejected.
        no_flavor=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            "http://127.0.0.1:$DIRECT_PORT/computeMetadata/v1/instance/service-accounts/default/token" || true)
        if [[ "$no_flavor" == "403" ]]; then
            ok "direct probe: missing Metadata-Flavor header gets 403"
        else
            fail "direct probe: missing Metadata-Flavor header gets 403" "got: $no_flavor"
        fi
    else
        fail "direct probe: binary reported PORT=" "status='$direct_line' log=$(cat "$GCP_LOG_FILE")"
    fi
    kill "$GCP_DIRECT_PID" 2>/dev/null || true
    wait "$GCP_DIRECT_PID" 2>/dev/null || true
else
    fail "ccode-gcp-metadata binary present" "binary not found at $GCP_BIN — run \`make\` first"
fi

# Preflight failure surfaces clearly. Make the stub gcloud fail on
# print-access-token to simulate missing tokenCreator IAM.
mkdir -p "$TMP/gcp-fail-bin"
cat > "$TMP/gcp-fail-bin/gcloud" <<'STUB'
#!/bin/bash
echo "ERROR: (gcloud.auth.print-access-token) Permission denied (stubbed)" >&2
exit 1
STUB
chmod +x "$TMP/gcp-fail-bin/gcloud"
out_preflight=$(PATH="$TMP/gcp-fail-bin:$PATH" CCODE_SRC="$TEST_RW" \
                CCODE_GCP_IMPERSONATE="$TEST_SA" "$SCRIPT" 2>&1 || true)
if grep -q 'impersonation preflight failed' <<<"$out_preflight"; then
    ok "preflight failure surfaces with a clear message"
else
    fail "preflight failure surfaces with a clear message" "got: $out_preflight"
fi

echo
echo "==== summary ===="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then exit 1; fi
exit 0
