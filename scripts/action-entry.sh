#!/usr/bin/env bash
# The composite action's gate step.
#
# It exists as a file rather than an inline run block so that it can be read and tested. Two
# things about its control flow are deliberate and were both learned from real Actions runs.
#
# There is exactly one exit point. An early exit skipped the block that writes GITHUB_OUTPUT, so
# the "could not run" case produced no outputs at all, which is the case a caller most needs to
# distinguish from a clean one.
#
# It exits 0 even when the gate found something, and the exit code travels as an output instead.
# GitHub discards a composite action's outputs when the action fails, so failing here would
# throw away the counts. action.yml has a following step that reads exit-code and fails the job.
set -uo pipefail

: "${ACTION_PATH:?ACTION_PATH is not set. This script is meant to run from action.yml.}"

args=(--lockfile "${INPUT_LOCKFILE:-package-lock.json}")

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

code=0

# base-ref accepts either a git ref or a path to a lockfile, matching --base in the CLI. Only
# the git-ref case needs fetching, and testing for the file FIRST matters: a previous version
# ran `git rev-parse` on a path, got a failure, and refused to run at all.
if [ -n "${INPUT_BASE_REF:-}" ]; then
  if [ -f "$INPUT_BASE_REF" ]; then
    args+=(--base "$INPUT_BASE_REF")
  else
    # A shallow checkout is the default for actions/checkout, so the base commit is often
    # absent. Fetching it is cheap and the alternative is a confusing failure.
    if ! git rev-parse --verify --quiet "$INPUT_BASE_REF" >/dev/null 2>&1; then
      git fetch --depth=1 origin "$INPUT_BASE_REF" >/dev/null 2>&1 || true
    fi
    if git rev-parse --verify --quiet "$INPUT_BASE_REF" >/dev/null 2>&1; then
      args+=(--base "$INPUT_BASE_REF")
    else
      echo "install-gate: base-ref '$INPUT_BASE_REF' is neither a file in the working" >&2
      echo "install-gate: directory nor a ref in this checkout. Set fetch-depth: 0 on" >&2
      echo "install-gate: actions/checkout, or pass a ref that exists." >&2
      code=2
    fi
  fi
fi

if [ "$code" -eq 0 ]; then
  node "$ACTION_PATH/bin/install-gate.mjs" "${args[@]}"
  code=$?
fi

if [ "$code" -eq 2 ]; then
  echo "install-gate: the gate could not run, so nothing was checked. This is reported as a" >&2
  echo "install-gate: failure rather than a pass, because a green check on a run that never" >&2
  echo "install-gate: happened means the opposite of what it appears to mean." >&2
fi

# The CLI appends findings, blocking, review, added and unknowns to GITHUB_OUTPUT itself, and it
# does not run at all on the code 2 path above, so those are written here as zeros with
# exit-code carrying the real story.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  if [ "$code" -eq 2 ]; then
    {
      echo "findings=0"
      echo "blocking=0"
      echo "review=0"
      echo "added=0"
      echo "unknowns=0"
    } >>"$GITHUB_OUTPUT"
  fi
  echo "report=$report" >>"$GITHUB_OUTPUT"
  echo "exit-code=$code" >>"$GITHUB_OUTPUT"
  exit 0
fi

exit "$code"
