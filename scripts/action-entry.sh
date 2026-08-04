#!/usr/bin/env bash
# The composite action's only step.
#
# It exists as a file rather than an inline run block so that it can be shellchecked, tested,
# and read. The exit code it returns is the exit code of the job.
set -uo pipefail

: "${ACTION_PATH:?ACTION_PATH is not set. This script is meant to run from action.yml.}"

args=(--lockfile "${INPUT_LOCKFILE:-package-lock.json}")

[ -n "${INPUT_BASE_REF:-}" ] && args+=(--base "$INPUT_BASE_REF")
[ -n "${INPUT_CONFIG:-}" ] && args+=(--config "$INPUT_CONFIG")
[ -n "${INPUT_FAIL_ON:-}" ] && args+=(--fail-on "$INPUT_FAIL_ON")
[ -n "${INPUT_MIN_AGE_DAYS:-}" ] && args+=(--min-age-days "$INPUT_MIN_AGE_DAYS")
[ -n "${INPUT_ON_UNKNOWN:-}" ] && args+=(--on-unknown "$INPUT_ON_UNKNOWN")
[ -n "${INPUT_REGISTRY:-}" ] && args+=(--registry "$INPUT_REGISTRY")

case "${INPUT_NODE_MODULES:-false}" in
  true|True|TRUE|1|yes) args+=(--node-modules) ;;
esac

report="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-gate-report.md"
args+=(--format markdown --output "$report" --json-out "${report%.md}.json")

# A base ref reachable by name is not guaranteed in a shallow checkout, which is the default
# for actions/checkout. Fetching it is cheap and the alternative is a confusing failure.
if [ -n "${INPUT_BASE_REF:-}" ] && ! git rev-parse --verify --quiet "$INPUT_BASE_REF" >/dev/null; then
  git fetch --depth=1 origin "$INPUT_BASE_REF" >/dev/null 2>&1 || true
  if ! git rev-parse --verify --quiet "$INPUT_BASE_REF" >/dev/null; then
    echo "install-gate: base ref '$INPUT_BASE_REF' is not in this checkout." >&2
    echo "install-gate: set fetch-depth: 0 on actions/checkout, or pass a ref that exists." >&2
    exit 2
  fi
fi

node "$ACTION_PATH/bin/install-gate.mjs" "${args[@]}"
code=$?

# The CLI appends findings, blocking, review, added and unknowns to GITHUB_OUTPUT itself. Only
# the report path is added here, because only this script knows where it put the file.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "report=$report" >>"$GITHUB_OUTPUT"
fi

if [ "$code" -eq 2 ]; then
  echo "install-gate: the gate could not run, so nothing was checked. Failing rather than" >&2
  echo "install-gate: passing, because a green check here would mean the opposite of what" >&2
  echo "install-gate: it appears to mean." >&2
fi

# This script exits 0 even when the gate found something, and the exit code travels as an
# output instead. A composite action that fails inside a step never has its outputs collected,
# so `blocking` and `added` came back as empty strings on exactly the runs where a caller needs
# them. The next step in action.yml reads exit-code and fails the job.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "exit-code=$code" >>"$GITHUB_OUTPUT"
else
  exit "$code"
fi
exit 0
