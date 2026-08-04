#!/usr/bin/env python3
"""Check that action.yml is real.

An action definition is the one part of this project that no test can execute, because running
it needs GitHub. That makes it exactly the place where a typo survives to production. A
`${{ inputs.base_ref }}` where the input is named `base-ref` interpolates to an empty string and
the gate quietly checks the whole lockfile instead of the diff, and the job still goes green.

So the definition is parsed and cross-checked against the code:

  1. it is valid YAML with the fields GitHub requires
  2. every declared input is passed to the entry script
  3. every value the entry script reads is a declared input
  4. every declared output is written to GITHUB_OUTPUT by something
  5. every step in a composite action declares a shell
  6. the paths it references exist

Requires PyYAML: python3 -m pip install pyyaml
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:
    import yaml
except ImportError:
    sys.exit(
        "PyYAML is not installed, so action.yml cannot be parsed and this check would be a\n"
        "no-op reporting success. Install it with:  python3 -m pip install pyyaml\n"
        "Without it the rest of the suite still covers the CLI, the policy and the exit codes,\n"
        "but nothing confirms the Action definition is even valid YAML."
    )


def fail(problems):
    print("action.yml FAILED")
    for p in problems:
        print("  " + p)
    sys.exit(1)


def main():
    path = os.path.join(ROOT, "action.yml")
    entry = os.path.join(ROOT, "scripts", "action-entry.sh")
    problems = []

    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as err:
        fail(["action.yml is not valid YAML: %s" % err])

    if not isinstance(doc, dict):
        fail(["action.yml did not parse to a mapping"])

    for field in ("name", "description", "runs"):
        if field not in doc:
            problems.append("missing required top-level field %r" % field)

    runs = doc.get("runs") or {}
    if runs.get("using") != "composite":
        problems.append("runs.using is %r, this action is written as a composite" % runs.get("using"))
    steps = runs.get("steps") or []
    if not steps:
        problems.append("runs.steps is empty")
    for i, step in enumerate(steps):
        if "shell" not in step:
            problems.append("step %d has no shell, which GitHub rejects at load time" % i)
        if "run" not in step and "uses" not in step:
            problems.append("step %d has neither run nor uses" % i)

    inputs = doc.get("inputs") or {}
    outputs = doc.get("outputs") or {}
    if not inputs:
        problems.append("no inputs declared")
    for name, spec in inputs.items():
        if not isinstance(spec, dict) or not spec.get("description"):
            problems.append("input %r has no description" % name)
        if spec.get("required") is not True and "default" not in spec:
            problems.append("input %r is optional with no default, so it interpolates to ''" % name)

    # --- 2 and 3: inputs reach the entry script, and the entry script reads only real inputs.
    step_env = {}
    for step in steps:
        step_env.update(step.get("env") or {})

    referenced = set()
    for value in step_env.values():
        referenced.update(re.findall(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}", str(value)))
    for step in steps:
        for key in ("run", "working-directory"):
            referenced.update(
                re.findall(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}", str(step.get(key, "")))
            )
        # An `if:` holds a bare expression, so inputs appear there without ${{ }} around them.
        # Requiring the braces here reported a genuinely wired input as unused.
        referenced.update(re.findall(r"\binputs\.([A-Za-z0-9_-]+)", str(step.get("if", ""))))

    unused = sorted(set(inputs) - referenced)
    if unused:
        problems.append(
            "declared but never passed to the step, so setting them does nothing: %s" % unused
        )
    undeclared = sorted(referenced - set(inputs))
    if undeclared:
        problems.append("referenced but not declared, interpolates to empty: %s" % undeclared)

    with open(entry, encoding="utf-8") as fh:
        entry_text = fh.read()

    env_names_used = set(re.findall(r"\$\{(INPUT_[A-Z0-9_]+)", entry_text))
    env_names_used |= set(re.findall(r'"\$(INPUT_[A-Z0-9_]+)"', entry_text))
    env_names_set = {k for k in step_env if k.startswith("INPUT_")}

    missing_env = sorted(env_names_used - env_names_set)
    if missing_env:
        problems.append(
            "%s is read by action-entry.sh but never set by action.yml, so it is always empty"
            % missing_env
        )
    unset_env = sorted(env_names_set - env_names_used)
    if unset_env:
        problems.append("%s is set by action.yml but never read by action-entry.sh" % unset_env)

    # --- 4: outputs exist and something writes them.
    step_ids = {s.get("id") for s in steps if s.get("id")}
    cli_text = open(os.path.join(ROOT, "src", "cli.js"), encoding="utf-8").read()
    m = re.search(r"const ghOutputs = \{(.*?)\};", cli_text, re.S)
    if not m:
        fail(["src/cli.js has no ghOutputs object, so the set of GITHUB_OUTPUT keys is unknown"])
    written_by_cli = set(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*[,:]", m.group(1), re.M))
    written_by_entry = set(re.findall(r'echo "([a-zA-Z0-9_-]+)=', entry_text))
    written = written_by_cli | written_by_entry

    for name, spec in outputs.items():
        value = str((spec or {}).get("value", ""))
        m = re.search(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}", value)
        if not m:
            problems.append("output %r has no steps.<id>.outputs.<name> value" % name)
            continue
        if m.group(1) not in step_ids:
            problems.append("output %r reads step id %r which does not exist" % (name, m.group(1)))
        if m.group(2) not in written:
            problems.append(
                "output %r reads %r, which nothing writes to GITHUB_OUTPUT. Written: %s"
                % (name, m.group(2), sorted(written))
            )

    # --- 5b: outputs must survive a failing run.
    #
    # A composite action that fails inside a step never has its outputs collected, so every
    # declared output came back as an empty string on exactly the runs a caller cares about.
    # That shipped, and only a real Actions run found it. The shape of the fix is asserted here
    # so it cannot quietly regress: the entry script records its exit code as an output, and a
    # later step reads that output and fails the job.
    if outputs:
        if "exit-code=$code" not in entry_text:
            problems.append(
                "action-entry.sh does not record its exit code as an output, so a failing run "
                "would fail inside the step and GitHub would collect none of the outputs"
            )
        gated = [s for s in steps
                 if re.search(r"steps\.[A-Za-z0-9_-]+\.outputs\.exit-code", str(s.get("if", "")))]
        if not gated:
            problems.append(
                "no step fails the job based on steps.<id>.outputs.exit-code, so either the "
                "gate never fails the build or it fails inside the step and loses its outputs"
            )
        else:
            for s in gated:
                if "exit 1" not in str(s.get("run", "")):
                    problems.append(
                        "the step gated on exit-code never exits non-zero, so a violation "
                        "would be reported and merged anyway"
                    )

    # --- 6: referenced paths exist.
    for rel in re.findall(r"\$ACTION_PATH/([A-Za-z0-9_./-]+)", entry_text):
        if not os.path.exists(os.path.join(ROOT, rel)):
            problems.append("action-entry.sh runs $ACTION_PATH/%s which does not exist" % rel)
    if "github.action_path" not in raw:
        problems.append("action.yml never passes github.action_path, so the step cannot find bin/")

    if problems:
        fail(problems)

    print(
        "action.yml parses: %d inputs all reaching the step, %d outputs all backed by a writer, "
        "%d composite step(s) with a shell" % (len(inputs), len(outputs), len(steps))
    )
    print("  inputs:  " + ", ".join(sorted(inputs)))
    print("  outputs: " + ", ".join(sorted(outputs)))
    print("  writers: " + json.dumps(sorted(written)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
