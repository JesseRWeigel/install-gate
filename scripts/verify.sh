#!/usr/bin/env bash
# Verification for install-gate.
#
# The product here is an exit code. Everything else is presentation. A gate that exits 0 when it
# should exit 1 is worse than no gate at all, because the green check is now evidence of safety
# that nobody re-examines. So the layers point at that:
#
#   1  unit suite, every positive test paired with a negative control
#   2  the exit code itself, proved 1 on a violation and 0 on a clean tree from a real CLI run
#   3  the exit code on a run that could NOT complete, which must be 2 rather than 0
#   4  an independent Python re-derivation that shares no code with the gate
#   5  that independence proved by walking the import graph with ast
#   6  the real trees, and the false-positive audit over every finding they produced
#   7  the Action definition parsed and cross-checked against the code that reads it
#   8  the page rebuilt byte for byte from the committed results
#   9  the README's own numbers checked against those results
#  10  sabotages, each proved to have applied AND to have changed the answer
#  11  hygiene
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
PY=python3
TREES="${INSTALL_GATE_TREES:-$HOME/Projects}"

pass=0; fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# A fixture project, built here rather than committed, so no node_modules ever enters git.
build_fixture() {
  local dir="$1" kind="$2"
  $PY - "$dir" "$kind" <<'PYEOF'
import json, os, sys
dir_, kind = sys.argv[1], sys.argv[2]
PKGS = {
    "left-pad@1.3.0": {"license": "MIT"},
    "ansi-styles@6.2.1": {"license": "MIT"},
    "esbuild@0.25.0": {"license": "MIT", "scripts": {"postinstall": "node install.js"}},
    "gpl-thing@2.0.0": {"license": "GPL-3.0-only"},
    "lgpl-thing@1.0.0": {"license": "LGPL-3.0-or-later"},
    "dual-thing@1.0.0": {"license": "(MPL-2.0 OR Apache-2.0)"},
}
keys = (["left-pad@1.3.0", "ansi-styles@6.2.1", "dual-thing@1.0.0"] if kind == "clean"
        else ["left-pad@1.3.0", "esbuild@0.25.0", "gpl-thing@2.0.0", "lgpl-thing@1.0.0",
              "dual-thing@1.0.0"])
packages = {"": {"name": "fixture", "version": "1.0.0"}}
for k in keys:
    name, version = k.rsplit("@", 1)
    spec = PKGS[k]
    ent = {"version": version,
           "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (name, name, version),
           "integrity": "sha512-fixture"}
    if spec.get("scripts"):
        ent["hasInstallScript"] = True
    ent["license"] = spec["license"]
    packages["node_modules/" + name] = ent
    d = os.path.join(dir_, "node_modules", name)
    os.makedirs(d, exist_ok=True)
    doc = {"name": name, "version": version, "license": spec["license"]}
    if spec.get("scripts"):
        doc["scripts"] = spec["scripts"]
    with open(os.path.join(d, "package.json"), "w") as fh:
        json.dump(doc, fh, indent=2)
os.makedirs(dir_, exist_ok=True)
with open(os.path.join(dir_, "package-lock.json"), "w") as fh:
    json.dump({"name": "fixture", "lockfileVersion": 3, "requires": True,
               "packages": packages}, fh, indent=2)
PYEOF
}

# A pnpm lockfile with no installed tree. Every fact about it is unknown, which is the state the
# gate must never render as clean, and the only fixture where that code path runs at all.
build_unknown_fixture() {
  local dir="$1"
  mkdir -p "$dir"
  {
    echo "lockfileVersion: '9.0'"
    echo
    echo "packages:"
    echo
    for spec in "left-pad@1.3.0" "esbuild@0.25.0"; do
      echo "  '$spec':"
      echo "    resolution: {integrity: sha512-fixture}"
      echo
    done
  } >"$dir/pnpm-lock.yaml"
}

echo "0. environment"
node --version | sed 's/^/        node /'
$PY --version | sed 's/^/        /'
if node --version >/dev/null 2>&1 && $PY --version >/dev/null 2>&1; then
  ok "node and python present"
else
  bad "node or python missing"
fi

echo
echo "1. unit suite, positives paired with negative controls"
if node --test "tests/*.test.mjs" >"$TMP/u.log" 2>&1; then
  ran=$(grep -oE '^# tests [0-9]+' "$TMP/u.log" | grep -oE '[0-9]+' | head -1)
  [ -n "$ran" ] || ran=$(grep -cE '^ok [0-9]+' "$TMP/u.log")
  ok "$ran unit tests passed"
  # A suite full of positives proves a gate that flags everything. Count the controls.
  controls=$(grep -c 'NEGATIVE CONTROL' tests/gate.test.mjs)
  if [ "$controls" -ge 10 ]; then
    ok "$controls negative controls in the suite, so a flag-everything gate would fail it"
  else
    bad "only $controls negative controls, which is too few to trust the positives"
  fi
else
  bad "unit suite"; grep -E 'not ok|AssertionError' "$TMP/u.log" | head -8 | sed 's/^/        /'
fi

echo
echo "2. the exit code, which is the product"
build_fixture "$TMP/clean" clean
build_fixture "$TMP/dirty" dirty
build_unknown_fixture "$TMP/unknown"
node bin/install-gate.mjs --cwd "$TMP/clean" --node-modules --min-age-days 0 \
  >"$TMP/clean.log" 2>&1; c_clean=$?
node bin/install-gate.mjs --cwd "$TMP/dirty" --node-modules --min-age-days 0 \
  >"$TMP/dirty.log" 2>&1; c_dirty=$?
if [ "$c_clean" -eq 0 ] && [ "$c_dirty" -eq 1 ]; then
  ok "exit 0 on a clean tree and exit 1 on a real violation"
  grep -E '^(BLOCK|REVIEW)' "$TMP/dirty.log" | head -3 | sed 's/^/        /'
  tail -1 "$TMP/clean.log" | sed 's/^/        clean: /'
else
  bad "expected 0 then 1, got $c_clean and $c_dirty"
  tail -4 "$TMP/dirty.log" | sed 's/^/        /'
fi
# The dual license in the clean fixture is the control that matters: "(MPL-2.0 OR Apache-2.0)"
# contains the string MPL, and a gate matching on substrings would block a clean tree.
if grep -q 'dual-thing' "$TMP/clean.log"; then
  bad "the clean tree was flagged over a permissive dual license, which is a false positive"
else
  ok "a permissive dual license containing the string MPL did not trip the gate"
fi
# And an already-present risky package must not fire, because it is not part of the change.
cp "$TMP/dirty/package-lock.json" "$TMP/dirty/base.json"
node bin/install-gate.mjs --cwd "$TMP/dirty" --base base.json --node-modules --min-age-days 0 \
  >"$TMP/same.log" 2>&1; c_same=$?
if [ "$c_same" -eq 0 ] && grep -q '0 package(s) added' "$TMP/same.log"; then
  ok "an unchanged lockfile adds nothing and exits 0"
else
  bad "an unchanged lockfile did not come back clean (exit $c_same)"
fi

echo
echo "3. a run that could not complete must not look like a clean one"
node bin/install-gate.mjs --cwd "$TMP/clean" --lockfile nope.json >"$TMP/e1.log" 2>&1; e1=$?
node bin/install-gate.mjs --cwd "$TMP/clean" --frobnicate >"$TMP/e2.log" 2>&1; e2=$?
printf 'x' >"$TMP/clean/broken.json"
node bin/install-gate.mjs --cwd "$TMP/clean" --config broken.json >"$TMP/e3.log" 2>&1; e3=$?
if [ "$e1" -eq 2 ] && [ "$e2" -eq 2 ] && [ "$e3" -eq 2 ]; then
  ok "missing lockfile, bad flag and unparseable config all exit 2, not 0"
  head -1 "$TMP/e1.log" | sed 's/^/        /'
else
  bad "expected 2, 2, 2 and got $e1, $e2, $e3"
fi

echo
echo "4. an independent re-derivation, sharing no code"
node bin/install-gate.mjs --cwd "$TMP/dirty" --node-modules --min-age-days 0 \
  --format json --quiet --json-out "$TMP/dirty.json" >/dev/null 2>&1
node bin/install-gate.mjs --cwd "$TMP/unknown" --lockfile pnpm-lock.yaml --min-age-days 0 \
  --format json --quiet --json-out "$TMP/unknown.json" >/dev/null 2>&1
if $PY scripts/check_independent.py --tree "$TMP/dirty" --lockfile package-lock.json \
     --gate-json "$TMP/dirty.json" --node-modules >"$TMP/i.log" 2>&1; then
  sed 's/^/        /' "$TMP/i.log"; ok "the independent checker agrees on the fixture"
else
  bad "the independent checker disagrees"; sed 's/^/        /' "$TMP/i.log" | head -6
fi
# The control for layer 4. A checker that agrees with everything is worth nothing, so a copy of
# the gate with its license classifier inverted must make the checker disagree.
CTL="$TMP/ctl"; rm -rf "$CTL"; mkdir -p "$CTL"
tar -cf - --exclude=.git --exclude=node_modules -C "$ROOT" . | tar -xf - -C "$CTL"
if $PY -c "
import pathlib, sys
p = pathlib.Path('$CTL/src/spdx.js'); t = p.read_text()
old = '    [PERMISSIVE, \"permissive\"],'
if old not in t:
    sys.exit('control sabotage did not apply, the line is not there')
p.write_text(t.replace(old, '    [PERMISSIVE, \"strong-copyleft\"],', 1))
"; then
  node "$CTL/bin/install-gate.mjs" --cwd "$TMP/clean" --node-modules --min-age-days 0 \
    --format json --quiet --json-out "$TMP/ctl.json" >/dev/null 2>&1
  if $PY -c "
import json, sys
d = json.load(open('$TMP/ctl.json'))
blocks = [f for f in d['findings'] if f['severity'] == 'block']
sys.exit(0 if blocks else 1)
"; then
    if $PY scripts/check_independent.py --tree "$TMP/clean" --lockfile package-lock.json \
         --gate-json "$TMP/ctl.json" --node-modules >"$TMP/i2.log" 2>&1; then
      bad "the checker agreed with a gate whose OR resolution is inverted, so it checks nothing"
    else
      printf '        %s\n' "$(sed -n 2p "$TMP/i2.log" | cut -c1-100)"
      ok "and it disagrees when the gate is broken, so its agreement means something"
    fi
  else
    bad "the layer 4 control changed nothing observable, so it proves nothing"
  fi
else
  bad "the layer 4 control could not be set up"
fi

echo
echo "5. the checker really is independent"
if $PY - <<'PYEOF' >"$TMP/imp.log" 2>&1; then
import ast, pathlib, sys

src = pathlib.Path("scripts/check_independent.py")
tree = ast.parse(src.read_text())

ALLOWED = {"argparse", "json", "os", "re", "sys"}
imported = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imported.update(a.name.split(".")[0] for a in node.names)
    elif isinstance(node, ast.ImportFrom):
        if node.level:
            sys.exit("relative import found, which would reach into the project")
        imported.add((node.module or "").split(".")[0])

extra = imported - ALLOWED
if extra:
    sys.exit(f"imports beyond the standard library set: {sorted(extra)}")

# Importing nothing is not enough on its own. Shelling out to the gate, or exec-ing its source,
# would reintroduce the shared code through a side door.
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        fn = node.func
        name = getattr(fn, "attr", None) or getattr(fn, "id", None)
        if name in {"system", "run", "Popen", "check_output", "call", "exec", "eval",
                    "import_module", "__import__"}:
            sys.exit(f"calls {name}(), which could re-enter the code being checked")

# And it must not read the gate's source as data either. Only string CONSTANTS are inspected,
# not the file text, because the module docstring legitimately talks about the implementation
# and a plain substring search over the whole file flags its own explanation of the rule.
docstrings = set()
for node in ast.walk(tree):
    if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        doc = ast.get_docstring(node, clean=False)
        if doc is not None:
            docstrings.add(doc)

MARKERS = ("spdx.js", "policy.js", "lockfile.js", "evidence.js", "report.js", "cli.js",
           "install-gate.mjs", "src/")
for node in ast.walk(tree):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value in docstrings:
            continue
        for marker in MARKERS:
            if marker in node.value:
                sys.exit(f"a string constant on line {node.lineno} names {marker!r}, so this "
                         "checker may be reading the implementation rather than the data")

print(f"imports only {sorted(imported)}; no subprocess, no exec, and no string constant "
      f"naming a module of the gate")
PYEOF
  sed 's/^/        /' "$TMP/imp.log"; ok "no shared code with the gate"
else
  bad "$(cat "$TMP/imp.log")"
fi

echo
echo "6. real dependency trees and the false-positive audit"
if [ -d "$TREES" ] && [ -n "$(ls -d "$TREES"/*/node_modules 2>/dev/null | head -1)" ]; then
  n_trees=$(ls -d "$TREES"/*/node_modules 2>/dev/null | wc -l)
  printf '        %s trees found\n' "$n_trees"
  # Every real tree, re-derived independently. This is the check that would catch the gate
  # mis-parsing a lockfile shape the fixtures do not contain.
  agreed=0; checked=0
  for nm in "$TREES"/*/node_modules; do
    d="$(dirname "$nm")"
    lf=""
    for cand in package-lock.json pnpm-lock.yaml yarn.lock; do
      [ -f "$d/$cand" ] && { lf="$cand"; break; }
    done
    [ -n "$lf" ] || continue
    checked=$((checked+1))
    node bin/install-gate.mjs --cwd "$d" --lockfile "$lf" --node-modules --min-age-days 0 \
      --format json --quiet --json-out "$TMP/real.json" >/dev/null 2>&1
    if $PY scripts/check_independent.py --tree "$d" --lockfile "$lf" \
         --gate-json "$TMP/real.json" --node-modules >"$TMP/real.log" 2>&1; then
      agreed=$((agreed+1))
    else
      printf '        disagreement on a real tree: %s\n' "$(sed -n 2p "$TMP/real.log")"
    fi
  done
  if [ "$checked" -gt 0 ] && [ "$agreed" -eq "$checked" ]; then
    ok "$agreed of $checked real trees re-derived independently with no disagreement"
  else
    bad "only $agreed of $checked real trees agreed"
  fi

  if $PY scripts/measure_real_trees.py >"$TMP/m.log" 2>&1; then
    tail -1 "$TMP/m.log" >/dev/null
    ok "the tree measurement reruns"
  else
    bad "the tree measurement failed"; tail -3 "$TMP/m.log" | sed 's/^/        /'
  fi
  if $PY scripts/audit_findings.py >"$TMP/a.log" 2>&1; then
    sed 's/^/        /' "$TMP/a.log" | head -8
    if $PY - <<'PYEOF' >"$TMP/aa.log" 2>&1; then
import json, pathlib, sys
a = json.loads(pathlib.Path("results/fp_audit.json").read_text())
if a["judged"] < 30:
    sys.exit(f"only {a['judged']} findings reached a verdict, too few to claim a rate")
if a["verdicts"].get("unaudited"):
    sys.exit(f"{a['verdicts']['unaudited']} findings have no verdict at all")
rate = a["false_positive_rate"]
if rate is None or rate > 0.05:
    sys.exit(f"false-positive rate is {rate}, which is above the 5% this project claims")
# The audit must be capable of returning a false positive, otherwise a rate of zero means the
# audit is broken rather than the gate being right.
src = pathlib.Path("scripts/audit_findings.py").read_text()
if src.count('"false-positive"') < 3:
    sys.exit("the audit has too few paths that can return false-positive to be trusted")
print(f"{a['judged']} findings judged, {a['verdicts'].get('false-positive', 0)} false positives, "
      f"{a['correct_but_low_value']} correct but low value")
PYEOF
      sed 's/^/        /' "$TMP/aa.log"; ok "the audit reaches a verdict on every finding"
    else
      bad "$(cat "$TMP/aa.log")"
    fi
  else
    bad "the audit failed"; tail -4 "$TMP/a.log" | sed 's/^/        /'
  fi

  if $PY scripts/measure_pr_noise.py >"$TMP/n.log" 2>&1; then
    if $PY - <<'PYEOF' >"$TMP/nn.log" 2>&1; then
import json, pathlib, sys
n = json.loads(pathlib.Path("results/pr_noise.json").read_text())
o = n["ordinary"]
if o["findings"]["n"] < 20:
    sys.exit(f"only {o['findings']['n']} real changes replayed, too few to describe noise")
if o["findings"]["median"] > 5:
    sys.exit(f"median of {o['findings']['median']} findings per change is noisy enough to be "
             "switched off")
# A gate that never fires is quiet for the wrong reason, and the median above would still pass.
if o["changes_that_would_block"] == 0:
    sys.exit("no replayed change would have blocked, so this measurement cannot tell a working "
             "gate from a broken one")
print(f"{o['findings']['n']} real changes replayed: median {o['findings']['median']} findings, "
      f"mean {o['findings']['mean']}, worst {o['findings']['max']}; "
      f"{o['changes_that_would_block']} would block")
PYEOF
      sed 's/^/        /' "$TMP/nn.log"; ok "noise measured on real history and within bounds"
    else
      bad "$(cat "$TMP/nn.log")"
    fi
  else
    bad "the noise measurement failed"; tail -4 "$TMP/n.log" | sed 's/^/        /'
  fi
else
  bad "no dependency trees at $TREES, so the real-tree numbers are unverified"
  printf '        %s\n' "Set INSTALL_GATE_TREES to a directory of JavaScript projects that have"
  printf '        %s\n' "both a lockfile and an installed node_modules, then rerun. Without it"
  printf '        %s\n' "layers 1 to 5 still cover the gate, but no number in the README is"
  printf '        %s\n' "checked against real data and the false-positive rate is unmeasured."
fi

echo
echo "7. the Action definition"
if $PY scripts/check_action.py >"$TMP/act.log" 2>&1; then
  sed 's/^/        /' "$TMP/act.log"; ok "action.yml parses and matches the code"
else
  bad "action.yml"; sed 's/^/        /' "$TMP/act.log" | head -8
fi
# Control: break the wiring and confirm the checker notices.
ACTL="$TMP/actl"; rm -rf "$ACTL"; mkdir -p "$ACTL"
tar -cf - --exclude=.git --exclude=node_modules -C "$ROOT" . | tar -xf - -C "$ACTL"
if $PY -c "
import pathlib, sys
p = pathlib.Path('$ACTL/action.yml'); t = p.read_text()
old = 'INPUT_BASE_REF: \${{ inputs.base-ref }}'
if old not in t:
    sys.exit('control did not apply')
p.write_text(t.replace(old, 'INPUT_BASE_REF: \${{ inputs.base_ref }}', 1))
"; then
  if (cd "$ACTL" && $PY scripts/check_action.py) >"$TMP/act2.log" 2>&1; then
    bad "check_action.py passed an action.yml referencing an input that does not exist"
  else
    printf '        %s\n' "$(sed -n 2p "$TMP/act2.log" | cut -c1-96)"
    ok "and it fails on a misspelled input, which is the typo it exists to catch"
  fi
else
  bad "the layer 7 control could not be set up"
fi

echo
echo "8. the page rebuilds from the committed results"
cp docs/index.html "$TMP/page.html" 2>/dev/null || true
if $PY scripts/build_docs.py >"$TMP/d.log" 2>&1; then
  sed 's/^/        /' "$TMP/d.log"
  if [ -f "$TMP/page.html" ] && cmp -s docs/index.html "$TMP/page.html"; then
    ok "docs/index.html is exactly what the results produce"
  elif [ -f "$TMP/page.html" ]; then
    bad "docs/index.html differs from a fresh build"; cp "$TMP/page.html" docs/index.html
  else
    ok "docs/index.html built (no previous copy)"
  fi
  # The page has to contain the numbers, not merely exist. A build that emitted an empty shell
  # would pass a file-exists check and every unit test at the same time.
  if $PY - <<'PYEOF' >"$TMP/pg.log" 2>&1; then
import json, pathlib, sys
page = pathlib.Path("docs/index.html").read_text()
t = json.loads(pathlib.Path("results/real_trees.json").read_text())["totals"]
a = json.loads(pathlib.Path("results/fp_audit.json").read_text())
want = [f"{t['installed_packages']:,}", str(t["installed_with_install_script"]),
        str(a["distinct_findings_audited"])]
missing = [w for w in want if w not in page]
if missing:
    sys.exit(f"the page does not contain {missing}")
if "<table" not in page or page.count("<tr") < 20:
    sys.exit("the page has almost no rows in it, so the tables did not render")
for name in t["distinct_script_packages"]:
    if name not in page:
        sys.exit(f"{name} runs an install script and is not named on the page")
print(f"the page carries all {len(want)} headline numbers and all "
      f"{len(t['distinct_script_packages'])} install-script package names")
PYEOF
    sed 's/^/        /' "$TMP/pg.log"; ok "the page contains the measured numbers"
  else
    bad "$(cat "$TMP/pg.log")"
  fi
else
  bad "the page could not be built"; tail -3 "$TMP/d.log" | sed 's/^/        /'
fi

echo
echo "9. the README says what the results say"
if $PY - <<'PYEOF' >"$TMP/rm.log" 2>&1; then
import json, pathlib, re, sys
readme = pathlib.Path("README.md").read_text()
t = json.loads(pathlib.Path("results/real_trees.json").read_text())["totals"]
a = json.loads(pathlib.Path("results/fp_audit.json").read_text())
n = json.loads(pathlib.Path("results/pr_noise.json").read_text())["ordinary"]

if "## Status" not in readme:
    sys.exit("README has no Status section")
if "VERIFY OK" not in readme:
    sys.exit("the Status section does not carry the verify script's own success line")
if "TODO" in readme:
    sys.exit("README still contains a TODO")

claims = {
    "installed packages": f"{t['installed_packages']:,}",
    "packages with install scripts": str(t["installed_with_install_script"]),
    "distinct install-script names": str(len(t["distinct_script_packages"])),
    "findings audited": str(a["distinct_findings_audited"]),
    "changes replayed": str(n["findings"]["n"]),
}
missing = {k: v for k, v in claims.items() if v not in readme}
if missing:
    sys.exit(f"the README does not state these measured values: {missing}")

# A pasted count goes stale the moment a test is added, so the number in the README has to
# match the number the suite actually reports.
m = re.search(r"(\d+)\s+unit tests", readme)
if not m:
    sys.exit("the README does not state a unit test count")
import subprocess
out = subprocess.run(["node", "--test", "--test-reporter=tap", "tests/*.test.mjs"],
                     capture_output=True, text=True)
real = re.search(r"^# pass (\d+)", out.stdout, re.M)
if not real:
    sys.exit("could not read the real test count from the runner")
if m.group(1) != real.group(1):
    sys.exit(f"the README says {m.group(1)} unit tests and the suite runs {real.group(1)}")
print(f"README states {len(claims)} measured values, all matching results/, and "
      f"{real.group(1)} unit tests, matching the suite")
PYEOF
  sed 's/^/        /' "$TMP/rm.log"; ok "the README's numbers are the measured ones"
else
  bad "$(cat "$TMP/rm.log")"
fi

echo
echo "10. sabotage"
# Each attack must be proved to have applied and proved to have changed the gate's answer before
# the suite's reaction to it means anything. An attack that is a no-op will make you weaken a
# check that was already correct.
attack() {
  local name="$1" file="$2" old="$3" new="$4"
  local dir="$TMP/a-$name"; rm -rf "$dir"; mkdir -p "$dir"
  tar -cf - --exclude=.git --exclude=node_modules -C "$ROOT" . | tar -xf - -C "$dir"
  if ! $PY - "$dir/$file" "$old" "$new" <<'PYEOF'
import pathlib, sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
t = p.read_text()
if old == new:
    sys.exit("SABOTAGE IS A NO-OP: old and new are identical")
if old not in t:
    sys.exit(f"SABOTAGE DID NOT APPLY: {old!r} is not in {path}")
p.write_text(t.replace(old, new, 1))
PYEOF
  then
    bad "sabotage \"$name\" did not apply, so it proves nothing"
    return
  fi

  # Proof the sabotage changed the observable output, on the two fixtures, before asking
  # whether anything caught it.
  node "$dir/bin/install-gate.mjs" --cwd "$TMP/dirty" --node-modules --min-age-days 0 \
    --format json --quiet --json-out "$dir/dirty.json" >/dev/null 2>&1
  node "$dir/bin/install-gate.mjs" --cwd "$TMP/clean" --node-modules --min-age-days 0 \
    --format json --quiet --json-out "$dir/clean.json" >/dev/null 2>&1
  node "$dir/bin/install-gate.mjs" --cwd "$TMP/unknown" --lockfile pnpm-lock.yaml \
    --min-age-days 0 --format json --quiet --json-out "$dir/unknown.json" >/dev/null 2>&1
  if ! $PY - "$dir" "$TMP/dirty.json" "$TMP/unknown.json" <<'PYEOF' >"$TMP/$name-diff.log" 2>&1
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
good = json.loads(pathlib.Path(sys.argv[2]).read_text())
good_unknown = json.loads(pathlib.Path(sys.argv[3]).read_text())
try:
    bad_dirty = json.loads((d / "dirty.json").read_text())
    bad_clean = json.loads((d / "clean.json").read_text())
    bad_unknown = json.loads((d / "unknown.json").read_text())
except (OSError, ValueError) as err:
    print(f"the sabotaged gate no longer produces output at all: {err}")
    sys.exit(0)

def shape(doc):
    return sorted((f["rule"], f["severity"], f["package"]) for f in doc["findings"])

if shape(bad_dirty) != shape(good) or bad_dirty["exitCode"] != good["exitCode"]:
    print(f"dirty fixture: exit {good['exitCode']} -> {bad_dirty['exitCode']}, "
          f"{len(good['findings'])} findings -> {len(bad_dirty['findings'])}")
    sys.exit(0)
if bad_clean["exitCode"] != 0 or bad_clean["findings"]:
    print(f"clean fixture: exit 0 -> {bad_clean['exitCode']}, "
          f"0 findings -> {len(bad_clean['findings'])}")
    sys.exit(0)
if shape(bad_unknown) != shape(good_unknown) or bad_unknown["unknowns"] != good_unknown["unknowns"]:
    print(f"unknown fixture: {good_unknown['unknowns']} unestablished facts -> "
          f"{bad_unknown['unknowns']}, {len(good_unknown['findings'])} findings -> "
          f"{len(bad_unknown['findings'])}")
    sys.exit(0)
sys.exit("the sabotage changed nothing observable, so it proves nothing about the suite")
PYEOF
  then
    bad "sabotage \"$name\" applied but changed no output, so it proves nothing"
    sed 's/^/        /' "$TMP/$name-diff.log" | head -2
    return
  fi
  printf '        %s: %s\n' "$name" "$(head -1 "$TMP/$name-diff.log")"

  local urc irc
  ( cd "$dir" && node --test "tests/*.test.mjs" ) >"$TMP/$name-u.log" 2>&1; urc=$?
  ( cd "$dir" && $PY scripts/check_independent.py --tree "$TMP/dirty" \
      --lockfile package-lock.json --gate-json "$dir/dirty.json" --node-modules ) \
      >"$TMP/$name-i.log" 2>&1; irc=$?
  printf '        %s: unit suite %s, independent checker %s\n' "$name" "$urc" "$irc"
  if [ "$urc" -ne 0 ] || [ "$irc" -ne 0 ]; then
    ok "sabotage \"$name\" is caught"
  else
    bad "sabotage \"$name\" changed the answer and nothing noticed"
  fi
}

# The gate stops gating: a violation no longer changes the exit code.
attack "exit-code-always-zero" "src/policy.js" \
  '  return findings.some((f) => (order[f.severity] ?? -1) >= threshold) ? 1 : 0;' \
  '  return 0;'
# An unknown fact is silently treated as a clean one, which is the failure this project is
# shaped around and the one a passing suite would most plausibly miss.
attack "unknown-becomes-clean" "src/evidence.js" \
  'export function unknownFact(reason) {
  return { value: null, known: false, source: reason };
}' \
  'export function unknownFact(reason) {
  return { value: false, known: true, source: reason };
}'
# npm omits hasInstallScript when false. Reading the omission as unknown looks harmless and
# turns every clean npm tree into a wall of unknowns.
attack "lockfile-flag-inverted" "src/lockfile.js" \
  '        hasInstallScript: ent.hasInstallScript === true,' \
  '        hasInstallScript: ent.hasInstallScript !== true,'
# The classic license bug: match on the substring instead of parsing the expression.
attack "license-by-substring" "src/spdx.js" \
  'export function classifyLicense(raw) {' \
  'export function classifyLicense(raw) {
  if (raw && String(raw).includes("GPL")) {
    return { class: "strong-copyleft", ids: [String(raw)], expression: String(raw), parsed: true };
  }'
# The install-script check reads a field that does not exist, so nothing ever has a script.
attack "install-scripts-never-seen" "src/evidence.js" \
  'const SCRIPT_KEYS = ["preinstall", "install", "postinstall"];' \
  'const SCRIPT_KEYS = ["preinstal", "instal", "postinstal"];'
# The diff stops diffing and everything looks like it was already there.
attack "nothing-is-ever-added" "src/cli.js" \
  '    const added = [...head.packages.values()].filter((e) => !baseKeys.has(e.key));' \
  '    const added = [];'
# Grouping swallows findings instead of summarising them, which would quietly hide real ones.
attack "collapse-drops-findings" "src/policy.js" \
  '    if (gk === null) {
      out.push(f);
      continue;
    }' \
  '    if (gk === null) {
      continue;
    }'

echo
echo "11. hygiene"
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  # A file containing a NUL is classified as binary by git and grep, and the scans below then
  # skip it entirely and report clean. This project had exactly that: a NUL separator in
  # src/policy.js made the whole file invisible to the credential scan.
  if $PY - "$ROOT" <<'PYEOF' >"$TMP/nul.log" 2>&1; then
import os, subprocess, sys
root = sys.argv[1]
files = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True,
                       check=True).stdout.split(b"\0")
names = [f.decode() for f in files if f]
bad = [n for n in names
       if os.path.isfile(os.path.join(root, n))
       and b"\0" in open(os.path.join(root, n), "rb").read()]
if bad:
    sys.exit("files containing NUL, invisible to every scan below: " + ", ".join(bad))
print(f"{len(names)} tracked files, none contain NUL, so the scans below can read all of them")
PYEOF
    sed 's/^/        /' "$TMP/nul.log"; ok "no tracked file is binary to the scans"
  else
    bad "$(cat "$TMP/nul.log")"
  fi

  hits=$(git -C "$ROOT" grep -In -e "/home/$(id -un)" -- . 2>/dev/null \
         | grep -vE '^(scripts/verify\.sh|README\.md):' || true)
  if [ -z "$hits" ]; then
    ok "no absolute home paths in tracked files"
  else
    bad "home paths in tracked files"; printf '%s\n' "$hits" | head -4 | sed 's/^/        /'
  fi

  keys=$(git -C "$ROOT" grep -In -E 'sk-[A-Za-z0-9]{20}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10}' \
         -- . 2>/dev/null || true)
  if [ -z "$keys" ]; then
    ok "no credential-shaped strings"
  else
    bad "possible credential"; printf '%s\n' "$keys" | head -3 | sed 's/^/        /'
  fi

  if git -C "$ROOT" ls-files | grep -q 'node_modules/'; then
    bad "node_modules is tracked"
  else
    ok "no node_modules is tracked"
  fi

  big=$(git -C "$ROOT" ls-files | while read -r f; do
          [ -f "$f" ] && [ "$(stat -c%s "$f")" -gt 800000 ] && echo "$f"; done || true)
  if [ -z "$big" ]; then
    ok "no tracked file over 800 KB"
  else
    bad "large files"; printf '%s\n' "$big" | head -3 | sed 's/^/        /'
  fi

  # Prose rules for this workspace: no em dashes, in any tracked text file.
  # The pattern is built rather than written, because a literal one here would make this check
  # fail on its own source the moment verify.sh became a tracked file. It did.
  em_pat=$(printf '\xe2\x80\x94')
  em=$(git -C "$ROOT" grep -In -- "$em_pat" -- '*.md' '*.js' '*.mjs' '*.py' '*.yml' '*.sh' \
       2>/dev/null || true)
  if [ -z "$em" ]; then
    ok "no em dashes in tracked prose"
  else
    bad "em dashes"; printf '%s\n' "$em" | head -3 | sed 's/^/        /'
  fi
else
  bad "not a git repo"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || { echo "VERIFY FAILED"; exit 1; }
echo "VERIFY OK"
