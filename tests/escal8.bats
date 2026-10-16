#!/usr/bin/env bats
# Bats-core test suite for Escal8.
# Run with: bats tests/escal8.bats   (requires bats-core installed)
# See tests/run_tests.sh for a dependency-free equivalent subset of these
# cases, which is what CI runs in this sandbox where bats-core is not
# installable (no network access for package installation).

setup() {
    ROOT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    SCRIPT="$ROOT_DIR/dist/escal8.sh"
}

@test "help exits 0 and prints usage" {
    run "$SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"USAGE:"* ]]
}

@test "version prints tool name and a semver-like string" {
    run "$SCRIPT" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"Escal8 v"* ]]
}

@test "unknown profile is rejected with exit code 2" {
    run "$SCRIPT" --profile does-not-exist
    [ "$status" -eq 2 ]
}

@test "unsupported format is rejected with exit code 2" {
    run "$SCRIPT" --format yaml
    [ "$status" -eq 2 ]
}

@test "unknown flag is rejected with exit code 2" {
    run "$SCRIPT" --totally-bogus
    [ "$status" -eq 2 ]
}

@test "--checks limits execution to the named checks only" {
    run "$SCRIPT" --no-color --checks system
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
    [[ "$output" == *"System Information"* ]]
    [[ "$output" != *"SUID / SGID Binaries"* ]]
}

@test "quiet mode hides INFO findings but keeps the summary" {
    run "$SCRIPT" --no-color --checks system --quiet
    [[ "$output" != *"[INFO"* ]]
    [[ "$output" == *"Escal8 Summary"* ]]
}

@test "JSON report is written and parses" {
    out="$BATS_TEST_TMPDIR/report.json"
    run "$SCRIPT" --no-color --checks system,kernel --quiet --format json --output "$out"
    [ -s "$out" ]
    if command -v python3 >/dev/null 2>&1; then
        run python3 -c "import json; json.load(open('$out'))"
        [ "$status" -eq 0 ]
    fi
}

@test "HTML report is written and well-formed enough to contain a table" {
    out="$BATS_TEST_TMPDIR/report.html"
    run "$SCRIPT" --no-color --checks system --quiet --format html --output "$out"
    [ -s "$out" ]
    grep -q '<table>' "$out"
    grep -q '</html>' "$out"
}

@test "a world-writable PATH entry is reported as CRITICAL and drives exit code 2" {
    fixture_dir="$BATS_TEST_TMPDIR/writable_path_dir"
    mkdir -p "$fixture_dir"
    chmod 777 "$fixture_dir"
    PATH="$fixture_dir:$PATH" run "$SCRIPT" --no-color --checks path --quiet
    [ "$status" -eq 2 ]
}

@test "unknown --checks name is rejected with exit code 2, nothing runs" {
    run "$SCRIPT" --checks system,totally_bogus --no-color
    [ "$status" -eq 2 ]
    [[ "$output" == *"totally_bogus"* ]]
    [[ "$output" != *"Linux Privilege Escalation Enumeration"* ]]
}

@test "check coverage section distinguishes completed from unrequested checks" {
    run "$SCRIPT" --no-color --checks system,kernel
    [[ "$output" == *"Check Coverage"* ]]
    completed_line="$(printf '%s\n' "$output" | grep -E '^\s*Completed')"
    [[ "$completed_line" == *"system"* ]]
    unrequested_line="$(printf '%s\n' "$output" | grep -E '^\s*Unrequested')"
    [[ "$unrequested_line" == *"suid"* ]]
    [[ "$completed_line" != *"suid"* ]]
}

@test "a check module that exits non-zero is classified Failed, not silently Completed" {
    faildir="$BATS_TEST_TMPDIR/faildir"
    mkdir -p "$faildir"
    cp "$SCRIPT" "$faildir/escal8.sh"
    sed -i 's/system)       run_check_system ;;/system)       run_check_system; return 1 ;;/' "$faildir/escal8.sh"
    run bash "$faildir/escal8.sh" --no-color --checks system,kernel
    failed_line="$(printf '%s\n' "$output" | grep -E '^\s*Failed')"
    [[ "$failed_line" == *"system"* ]]
    [[ "$output" == *"exited unexpectedly"* ]]
}

@test "secure temp directory: pre-existing symlink at a candidate path is refused, not followed" {
    source "$ROOT_DIR/src/02_utils.sh"
    target="$BATS_TEST_TMPDIR/target"
    link="$BATS_TEST_TMPDIR/link"
    mkdir -p "$target"
    ln -s "$target" "$link"
    run _escal8_mkdir_secure "$link"
    [ "$status" -ne 0 ]
    # the symlink's target must remain empty - nothing was written through it
    [ -z "$(ls -A "$target" 2>/dev/null)" ]
}

@test "JSON escaping round-trips quotes, backslashes, tabs, and control characters" {
    skip_if_no_python() { command -v python3 >/dev/null 2>&1 || skip "python3 not available"; }
    skip_if_no_python
    source "$ROOT_DIR/src/90_report.sh"
    input="$(printf 'say "hi"\tC:\\win\x07bell')"
    escaped="$(_escal8_json_escape "$input")"
    printf '{"v": "%s"}' "$escaped" > "$BATS_TEST_TMPDIR/t.json"
    printf '%s' "$input" > "$BATS_TEST_TMPDIR/expected"
    run python3 -c "
import json,sys
d = json.load(open('$BATS_TEST_TMPDIR/t.json'))
expected = open('$BATS_TEST_TMPDIR/expected').read()
sys.exit(0 if d['v'] == expected else 1)
"
    [ "$status" -eq 0 ]
}

@test "root-aware permission check: a mode-640 file is not flagged, a mode-666 file is" {
    source "$ROOT_DIR/src/02_utils.sh"
    f="$BATS_TEST_TMPDIR/sensitive"
    echo x > "$f"
    chmod 640 "$f"
    run escal8_effective_access "$f" w
    [ "$status" -eq 1 ]
    chmod 666 "$f"
    run escal8_effective_access "$f" w
    [ "$status" -eq 0 ]
}

@test "missing optional tools are reported as SKIP, not errors" {
    mintools_dir="$BATS_TEST_TMPDIR/mintools"
    mkdir -p "$mintools_dir"
    for b in bash cat grep sed awk sort uniq head tail tr wc date ps id hostname uname basename dirname; do
        p="$(command -v "$b" 2>/dev/null)"
        [ -n "$p" ] && ln -sf "$p" "$mintools_dir/$b"
    done
    PATH="$mintools_dir" run "$SCRIPT" --no-color --profile full
    [[ "$output" == *"SKIP"*"find not available"* ]]
    [[ "$output" != *"command not found"* ]]
}

@test "new process and credential checks are registered and runnable" {
    run "$SCRIPT" --list-checks
    [ "$status" -eq 0 ]
    [[ "$output" == *"processes"* ]]
    [[ "$output" == *"credentials"* ]]
    run "$SCRIPT" --no-color --checks processes
    [[ "$output" == *"Privileged Process Paths"* ]]
    run "$SCRIPT" --no-color --checks credentials
    [[ "$output" == *"Potential Credential Files"* ]]
}

@test "secret-like environment values are redacted from findings" {
    run env API_KEY=escal8-bats-secret "$SCRIPT" --no-color --checks historyenv
    [[ "$output" == *"API_KEY=<redacted>"* ]]
    [[ "$output" != *"escal8-bats-secret"* ]]
}


@test "ACL parser ignores ineffective masked write permission" {
    source "$ROOT_DIR/src/27_check_acl.sh"
    acl=$'user:1001:rwx #effective:r-x\ngroup:1002:r--'
    run _escal8_acl_has_effective_write "$acl" 1001 " 1001 1002 " 1002
    [ "$status" -ne 0 ]
}

@test "ACL parser matches numeric current-user entry by permission field, not username text" {
    source "$ROOT_DIR/src/27_check_acl.sh"
    acl=$'user:1001:r--\ngroup:1002:r--'
    run _escal8_acl_has_effective_write "$acl" 1001 " 1001 1002 " 1002
    [ "$status" -ne 0 ]
}

@test "ACL parser detects effective write for matching numeric group" {
    source "$ROOT_DIR/src/27_check_acl.sh"
    acl=$'group:1002:rwx #effective:rwx'
    run _escal8_acl_has_effective_write "$acl" 1001 " 1001 1002 " 1002
    [ "$status" -eq 0 ]
}

@test "version is bumped for the audited release" {
    run "$SCRIPT" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"1.3.0"* ]]
}
