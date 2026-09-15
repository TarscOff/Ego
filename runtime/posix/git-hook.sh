#!/bin/sh
# EGO git hook shim (generated copy lives in .harness/hooks/). Runs every chained pre-existing hook saved as
# <name>.pre-ego, <name>.pre-ego.1, ... in the hooks directory, then the EGO check. git's stdin (pre-push ref lines)
# is captured once so a chained hook cannot consume it. Fails non-zero when the launcher is missing.
# Usage: git-hook.sh <name> <hooks-dir> [args]
name="$1"; hooksdir="$2"; shift 2
input=""
if [ "$name" = "pre-push" ]; then input="$(cat)"; fi
if [ -n "$hooksdir" ]; then
  for chained in "$hooksdir/$name.pre-ego" "$hooksdir/$name.pre-ego".*; do
    [ -f "$chained" ] || continue
    # husky user hooks need not be executable: run those with sh
    if [ -x "$chained" ]; then run="$chained"; else run="sh $chained"; fi
    if [ "$name" = "pre-push" ]; then printf '%s\n' "$input" | $run "$@" || exit $?
    else $run "$@" </dev/null || exit $?
    fi
  done
fi
if ! command -v harness >/dev/null 2>&1; then
  echo "EGO: harness launcher not found on PATH; git $name check cannot run (failing closed)" >&2
  exit 1
fi
if [ "$name" = "pre-push" ]; then printf '%s\n' "$input" | harness hook git "$name" "$@"
else harness hook git "$name" "$@" </dev/null
fi
