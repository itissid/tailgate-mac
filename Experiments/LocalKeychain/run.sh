#!/bin/bash
# Dummy-only learning test. Default/--preflight stops before any Keychain action.
set -euo pipefail
umask 077
root=$(cd "$(dirname "$0")" && pwd)
exec /usr/bin/python3 -B "$root/runner.py" "$@"
