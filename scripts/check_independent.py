#!/usr/bin/env python3
"""An independent second opinion on what the gate reported.

This shares no code with the gate. It is a different language, it imports nothing from src/,
and it re-derives every fact from the raw inputs: the lockfile text and the installed
package.json files. Then it compares.

The reason for the rule is that a checker built on the thing it checks inherits that thing's
bugs and reports clean on output that is wrong. Here that risk is concrete. If the gate's SPDX
parser called "(MPL-2.0 OR Apache-2.0)" copyleft, a validator importing the same parser would
agree, and the only thing that catches it is a second implementation that reads the string
itself.

What it checks:
  * the set of added packages matches
  * each package's install-script fact matches, including whether it is known at all
  * each package's license string matches
  * the blocking findings match a policy applied independently

Usage:
    python3 scripts/check_independent.py --tree DIR --lockfile package-lock.json \\
        --gate-json out.json [--node-modules]
"""

import argparse
import json
import os
import re
import sys

SCRIPT_KEYS = ("preinstall", "install", "postinstall")

# Deliberately written out again rather than shared. If this list and the gate's list are both
# wrong in the same way, that is a real risk, and it is the risk the hand audit in the README
# covers. What this catches is the gate's list drifting or its parser mangling an expression.
PERMISSIVE = {
    "MIT", "ISC", "Apache-2.0", "Apache-1.1", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
    "BSD-4-Clause", "Python-2.0", "PSF-2.0", "Zlib", "libpng-2.0", "X11", "AFL-2.1", "AFL-3.0",
    "Artistic-2.0", "BSL-1.0", "CC-BY-3.0", "CC-BY-4.0", "OFL-1.1", "Ruby", "UPL-1.0",
    "Unicode-DFS-2016", "Unicode-3.0", "W3C", "curl", "NTP", "JSON",
}
PUBLIC_DOMAIN = {"CC0-1.0", "Unlicense", "0BSD", "MIT-0", "WTFPL", "BlueOak-1.0.0"}
WEAK = {
    "MPL-1.1", "MPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only",
    "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-2.1", "LGPL-3.0",
    "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "EUPL-1.1", "EUPL-1.2",
    "Apache-2.0-with-LLVM-exception", "OSL-3.0",
}
STRONG = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "GPL-1.0-only", "GPL-1.0-or-later", "CC-BY-SA-4.0", "CC-BY-SA-3.0",
}
NETWORK = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-1.0-only", "AGPL-1.0-or-later",
    "SSPL-1.0", "OSL-3.0-network", "EUPL-1.2-network",
}
PROPRIETARY = {
    "UNLICENSED", "CC-BY-NC-4.0", "CC-BY-NC-3.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0",
    "Commercial", "Proprietary",
}
RANK = {
    "public-domain": 0, "permissive": 1, "weak-copyleft": 2, "strong-copyleft": 3,
    "network-copyleft": 4, "proprietary": 5, "nonstandard": 6, "unknown": 7,
}
BLOCKING_CLASSES = {"strong-copyleft", "network-copyleft", "proprietary"}


# ----------------------------------------------------------------- licenses

def classify_id(ident):
    core = ident.rstrip("+")
    if " WITH " in core.upper():
        core = re.split(r"\s+WITH\s+", core, flags=re.I)[0].strip()
    for group, name in (
        (PUBLIC_DOMAIN, "public-domain"), (PERMISSIVE, "permissive"), (WEAK, "weak-copyleft"),
        (STRONG, "strong-copyleft"), (NETWORK, "network-copyleft"), (PROPRIETARY, "proprietary"),
    ):
        lowered = {g.lower() for g in group}
        if core in group or core.lower() in lowered:
            return name
    return "nonstandard"


def classify_expression(expr):
    """Recursive descent over the SPDX grammar, written from the grammar rather than from src/.

    Returns (class, parsed).
    """
    if expr is None or not str(expr).strip():
        return "unknown", False
    text = str(expr).strip()
    if re.match(r"^SEE LICEN[CS]E IN ", text, re.I):
        return "nonstandard", False

    tokens = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append((ch, ch))
            i += 1
            continue
        j = i
        while j < len(text) and not text[j].isspace() and text[j] not in "()":
            j += 1
        word = text[i:j]
        i = j
        upper = word.upper()
        tokens.append((upper, word) if upper in ("OR", "AND", "WITH") else ("id", word))
    if not tokens:
        return "nonstandard", False

    pos = [0]

    def atom():
        if pos[0] >= len(tokens):
            raise ValueError("end of input")
        kind, value = tokens[pos[0]]
        if kind == "(":
            pos[0] += 1
            inner = expression()
            if pos[0] >= len(tokens) or tokens[pos[0]][0] != ")":
                raise ValueError("unbalanced")
            pos[0] += 1
            return inner
        if kind != "id":
            raise ValueError("unexpected " + kind)
        pos[0] += 1
        ident = value
        if pos[0] < len(tokens) and tokens[pos[0]][0] == "WITH":
            pos[0] += 1
            if pos[0] >= len(tokens) or tokens[pos[0]][0] != "id":
                raise ValueError("WITH without exception")
            ident = ident + " WITH " + tokens[pos[0]][1]
            pos[0] += 1
        return classify_id(ident)

    def conjunction():
        left = atom()
        while pos[0] < len(tokens) and tokens[pos[0]][0] == "AND":
            pos[0] += 1
            right = atom()
            left = left if RANK[left] >= RANK[right] else right
        return left

    def expression():
        left = conjunction()
        while pos[0] < len(tokens) and tokens[pos[0]][0] == "OR":
            pos[0] += 1
            right = conjunction()
            left = left if RANK[left] <= RANK[right] else right
        return left

    try:
        result = expression()
        if pos[0] != len(tokens):
            raise ValueError("trailing tokens")
    except ValueError:
        return "nonstandard", False
    return result, True


# ----------------------------------------------------------------- lockfiles

def norm_license(doc):
    lic = doc.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return lic["type"]
    if isinstance(doc.get("licenses"), list):
        types = [x if isinstance(x, str) else (x or {}).get("type") for x in doc["licenses"]]
        types = [t for t in types if isinstance(t, str)]
        if len(types) == 1:
            return types[0]
        if types:
            return "(" + " OR ".join(types) + ")"
    return None


def read_npm(text):
    doc = json.loads(text)
    out = {}
    if isinstance(doc.get("packages"), dict):
        for path, ent in doc["packages"].items():
            if not path.startswith("node_modules/") or ent.get("link"):
                continue
            name = ent.get("name")
            if not name:
                name = path[path.rfind("node_modules/") + len("node_modules/"):]
            version = ent.get("version")
            if not name or not version:
                continue
            key = "%s@%s" % (name, version)
            out.setdefault(key, {
                "name": name,
                "version": version,
                "script": bool(ent.get("hasInstallScript")),
                "license": ent["license"] if isinstance(ent.get("license"), str) else None,
            })
        return out
    if isinstance(doc.get("dependencies"), dict):
        stack = [doc["dependencies"]]
        while stack:
            deps = stack.pop()
            for name, ent in deps.items():
                if not isinstance(ent, dict) or not ent.get("version"):
                    continue
                key = "%s@%s" % (name, ent["version"])
                out.setdefault(key, {"name": name, "version": ent["version"],
                                     "script": None, "license": None})
                if isinstance(ent.get("dependencies"), dict):
                    stack.append(ent["dependencies"])
    return out


def read_pnpm(text):
    out = {}
    in_packages = False
    for line in text.splitlines():
        if re.match(r"^packages:\s*$", line):
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and not line[0].isspace():
            break
        m = re.match(r"^ {2}(?:'([^']+)'|\"([^\"]+)\"|([^\s:][^:]*)):\s*$", line)
        if not m:
            continue
        raw = m.group(1) or m.group(2) or m.group(3)
        if raw.startswith("/"):
            body = raw[1:]
            slash = body.rfind("/")
            if slash == -1:
                continue
            name, version = body[:slash], re.split(r"[_(]", body[slash + 1:])[0]
        else:
            body = raw.split("(")[0]
            at = body.rfind("@")
            if at <= 0:
                continue
            name, version = body[:at], body[at + 1:]
        if not name or not version or not version[0].isdigit():
            continue
        out.setdefault("%s@%s" % (name, version),
                       {"name": name, "version": version, "script": None, "license": None})
    return out


def read_yarn(text):
    out = {}
    specs, version = [], None
    def flush():
        if specs and version:
            spec = specs[0].strip().strip('"').strip("'")
            at = spec.rfind("@")
            if at > 0:
                name = spec[:at]
                out.setdefault("%s@%s" % (name, version),
                               {"name": name, "version": version, "script": None, "license": None})
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            flush()
            specs, version = [s.strip() for s in line.rstrip(":").split(",")], None
            continue
        m = re.match(r'^ {2}version:?\s+"?([^"\s]+)"?', line)
        if m:
            version = m.group(1)
    flush()
    return out


def read_lockfile(path):
    base = os.path.basename(path)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if base.endswith(".json"):
        return read_npm(text)
    if base.startswith("pnpm-lock"):
        return read_pnpm(text)
    if base.startswith("yarn.lock"):
        return read_yarn(text)
    sys.exit("unrecognised lockfile: " + base)


# ----------------------------------------------------------------- installed tree

def index_installed(root):
    """Walk every package.json under node_modules, including the pnpm store."""
    out = {}
    top = os.path.join(root, "node_modules")
    if not os.path.isdir(top):
        return out
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        if "package.json" not in filenames:
            continue
        try:
            with open(os.path.join(dirpath, "package.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        name, version = doc.get("name"), doc.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        key = "%s@%s" % (name, version)
        if key in out:
            continue
        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
        out[key] = {
            "script": any(
                isinstance(scripts.get(k), str) and scripts[k].strip() for k in SCRIPT_KEYS
            ),
            "license": norm_license(doc),
        }
    return out


# ----------------------------------------------------------------- comparison

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True)
    ap.add_argument("--lockfile", required=True)
    ap.add_argument("--base")
    ap.add_argument("--gate-json", required=True)
    ap.add_argument("--node-modules", action="store_true")
    args = ap.parse_args()

    head = read_lockfile(os.path.join(args.tree, args.lockfile))
    base = read_lockfile(args.base) if args.base else {}
    added = {k: v for k, v in head.items() if k not in base}

    installed = index_installed(args.tree) if args.node_modules else {}

    with open(args.gate_json, encoding="utf-8") as fh:
        gate = json.load(fh)

    problems = []

    # 1. the same set of packages was judged
    gate_added = set(gate["added"])
    if gate_added != set(added):
        only_gate = sorted(gate_added - set(added))[:6]
        only_here = sorted(set(added) - gate_added)[:6]
        problems.append(
            "added sets differ: gate has %d, this checker has %d; only-gate=%s only-checker=%s"
            % (len(gate_added), len(added), only_gate, only_here)
        )

    # 2. the same facts, including which facts are unknown
    detail = {d["package"]: d for d in gate["addedDetail"]}
    script_mismatch, license_mismatch = [], []
    for key, ent in added.items():
        d = detail.get(key)
        if d is None:
            problems.append("gate reported no detail for %s" % key)
            continue

        inst = installed.get(key)
        if inst is not None:
            want_script, want_known = inst["script"], True
            want_license = inst["license"] if inst["license"] is not None else ent["license"]
        else:
            want_script, want_known = ent["script"], ent["script"] is not None
            want_license = ent["license"]

        got = d["installScript"]
        if got["known"] != want_known or (want_known and bool(got["value"]) != bool(want_script)):
            script_mismatch.append(
                "%s: gate says known=%s value=%s, checker says known=%s value=%s"
                % (key, got["known"], got["value"], want_known, want_script)
            )

        gl = d["license"]
        want_license_known = want_license is not None
        if gl["known"] != want_license_known or (want_license_known and gl["value"] != want_license):
            license_mismatch.append(
                "%s: gate says %r, checker says %r" % (key, gl.get("value"), want_license)
            )

    problems.extend(script_mismatch[:8])
    problems.extend(license_mismatch[:8])
    if len(script_mismatch) > 8:
        problems.append("...and %d more install-script mismatches" % (len(script_mismatch) - 8))
    if len(license_mismatch) > 8:
        problems.append("...and %d more license mismatches" % (len(license_mismatch) - 8))

    # 3. the blocking set, derived independently under the gate's documented default policy
    allowlist = set()
    cfg_path = os.path.join(args.tree, ".install-gate.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                for a in (json.load(fh).get("allowInstallScripts") or []):
                    allowlist.add(a if isinstance(a, str) else a.get("name"))
        except (OSError, ValueError):
            pass

    expect_script_block, expect_license_block = set(), set()
    for key, ent in added.items():
        inst = installed.get(key)
        script = inst["script"] if inst is not None else ent["script"]
        lic = (inst["license"] if inst is not None and inst["license"] is not None
               else ent["license"])
        if script and ent["name"] not in allowlist:
            expect_script_block.add(key)
        cls, _ = classify_expression(lic)
        if lic is not None and cls in BLOCKING_CLASSES:
            expect_license_block.add(key)

    got_script_block, got_license_block = set(), set()
    for f in gate["findings"]:
        if f["severity"] != "block":
            continue
        members = f.get("packages") or [f["package"]]
        if f["rule"] == "install-script":
            got_script_block.update(members)
        elif f["rule"] in ("license-class", "license-unparsed"):
            got_license_block.update(members)

    if got_script_block != expect_script_block:
        problems.append(
            "install-script blocks differ: only-gate=%s only-checker=%s"
            % (sorted(got_script_block - expect_script_block)[:6],
               sorted(expect_script_block - got_script_block)[:6])
        )
    if got_license_block != expect_license_block:
        problems.append(
            "license blocks differ: only-gate=%s only-checker=%s"
            % (sorted(got_license_block - expect_license_block)[:6],
               sorted(expect_license_block - got_license_block)[:6])
        )

    # 4. the exit code has to follow from the findings
    should_exit = 1 if any(f["severity"] == "block" for f in gate["findings"]) else 0
    if gate["exitCode"] != should_exit:
        problems.append(
            "exit code %s does not follow from the findings, expected %s"
            % (gate["exitCode"], should_exit)
        )

    if problems:
        print("DISAGREEMENT")
        for p in problems:
            print("  " + p)
        return 1

    print(
        "agrees on %d added packages, %d install-script blocks, %d license blocks, exit %d"
        % (len(added), len(expect_script_block), len(expect_license_block), gate["exitCode"])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
