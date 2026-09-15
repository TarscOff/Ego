#!/bin/sh
# EGO hook shim (generated copy lives in .harness/hooks/). Fails closed: when the harness launcher is not resolvable
# the agent host receives exit 2, which blocks the action, and a one-line message. Usage: ego-hook.sh <host> <event>
if ! command -v harness >/dev/null 2>&1; then
  echo "EGO: harness launcher not found on PATH; failing closed (install @tarscoff/ego globally or fix PATH)" >&2
  exit 2
fi
harness hook "$1" "$2"
code=$?
[ "$code" -eq 0 ] && exit 0
# any failure (crash, missing runtime, exit 1) blocks: exit 2 is the only code every host treats as a blocking error
exit 2
