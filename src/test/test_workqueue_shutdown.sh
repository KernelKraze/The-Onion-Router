#!/bin/sh

BIN="${builddir:-.}/src/test/test_workqueue_shutdown"

# Each argument builds a different state to free the pool from, and a failure
# in one says nothing about the others, so run all three and report the first
# that breaks rather than stopping at it.
rc=0
for mode in busy idle update; do
    case "$mode" in
        busy) "$BIN" ;;
        *)    "$BIN" "$mode" ;;
    esac || { echo "workqueue shutdown: $mode failed"; rc=1; }
done
exit $rc
