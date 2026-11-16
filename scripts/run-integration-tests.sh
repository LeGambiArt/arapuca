#!/usr/bin/env bash
# Run the Linux integration suites with skip accounting.
#
# The supervisor/UDS-policy suites gate on host capabilities (Yama
# ptrace_scope, userns availability, python3, ...). A gated test that
# skips prints "skipping:" and returns success — so a restricted
# runner reports a green suite that validated nothing. This wrapper
# fails when EVERY test in a suite skipped, so a capability regression
# on the CI runner (or a test that silently stopped running) turns
# red instead of green.
#
# Usage: scripts/run-integration-tests.sh [cargo test args...]

set -uo pipefail

suites=(
    adversarial
    supervisor
    uds_policy
    unix_sockets
    unotify
    pidns
    userns
    fd_inheritance
    helper_hardening
)

overall=0
for suite in "${suites[@]}"; do
    log=$(mktemp)
    if ! cargo test --test "$suite" "$@" 2>&1 | tee "$log"; then
        echo "FAIL: suite $suite failed" >&2
        overall=1
        rm -f "$log"
        continue
    fi
    # tail, not head: head closes the pipe early, which under pipefail
    # makes sed exit 141 and can leave the count empty.
    passed=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' "$log" | tail -1)
    skipped=$(grep -c 'skipping:' "$log" || true)
    if [ -z "$passed" ]; then
        echo "FAIL: suite $suite produced no result line — it did not run" >&2
        overall=1
        rm -f "$log"
        continue
    fi
    if [ "$passed" -gt 0 ] && [ "$skipped" -ge "$passed" ]; then
        echo "FAIL: suite $suite ran $passed tests, ALL skipped — validated nothing (host capabilities?)" >&2
        overall=1
    else
        echo "ok: suite $suite — $passed passed, $skipped skips" >&2
    fi
    rm -f "$log"
done

exit "$overall"
