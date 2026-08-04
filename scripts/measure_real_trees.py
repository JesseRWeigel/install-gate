#!/usr/bin/env python3
"""Measure the gate against real dependency trees.

This exists because every number in the README has to come from somewhere real. It walks a
directory of JavaScript projects, each with a lockfile and an installed node_modules, and
records four things:

  1. how many packages there actually are
  2. how many of them actually declare preinstall, install or postinstall
  3. what licenses actually appear
  4. how many findings the gate produces on each tree in its worst case, which is a first run
     where every package counts as newly added

It also compares what the lockfile CLAIMS about install scripts and licenses against what the
installed tarball's own package.json says, because those are different sources and the gap
between them is the honest limit of what a lockfile-only check can see.

Nothing from the scanned trees is written into the output except package names, versions and
license strings. Tree names are replaced with labels, and no filesystem path is recorded.

Usage:
    python3 scripts/measure_real_trees.py [--projects-dir DIR] [--out results/real_trees.json]

DIR defaults to $INSTALL_GATE_TREES, then to $HOME/Projects.
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter

SCRIPT_KEYS = ("preinstall", "install", "postinstall")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


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


def walk_installed(nm_root):
    """Yield (relative_path, package.json dict) for every real package directory."""
    for dirpath, dirnames, filenames in os.walk(nm_root):
        base = os.path.basename(dirpath)
        if base == ".bin":
            dirnames[:] = []
            continue
        if "package.json" not in filenames:
            continue
        parent = os.path.basename(os.path.dirname(dirpath))
        gparent = os.path.basename(os.path.dirname(os.path.dirname(dirpath)))
        # A package directory sits directly under node_modules/ or under node_modules/@scope/.
        if parent != "node_modules" and not (parent.startswith("@") and gparent == "node_modules"):
            continue
        doc = load_json(os.path.join(dirpath, "package.json"))
        if not isinstance(doc, dict) or not doc.get("name"):
            continue
        yield os.path.relpath(dirpath, os.path.dirname(nm_root)), doc


def measure_tree(project_dir, label):
    nm = os.path.join(project_dir, "node_modules")
    result = {
        "label": label,
        "installed_packages": 0,
        "installed_with_install_script": 0,
        "script_kinds": Counter(),
        "licenses": Counter(),
        "script_packages": [],
        "lockfile": None,
    }

    for rel, doc in walk_installed(nm):
        result["installed_packages"] += 1
        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
        hits = [k for k in SCRIPT_KEYS if isinstance(scripts.get(k), str) and scripts[k].strip()]
        if hits:
            result["installed_with_install_script"] += 1
            for h in hits:
                result["script_kinds"][h] += 1
            result["script_packages"].append(
                {
                    "package": f"{doc['name']}@{doc.get('version')}",
                    "scripts": {k: scripts[k] for k in hits},
                }
            )
        result["licenses"][str(norm_license(doc))] += 1

    lock = os.path.join(project_dir, "package-lock.json")
    if os.path.exists(lock):
        result["lockfile"] = compare_lock_to_tarballs(project_dir, lock)
    result["script_kinds"] = dict(result["script_kinds"])
    result["licenses"] = dict(result["licenses"])
    return result


def compare_lock_to_tarballs(project_dir, lock_path):
    """The honest core of this measurement.

    package-lock.json v2 and v3 carry hasInstallScript and license, both of which npm derived
    from registry metadata and the resolved tarball when it built the file. The installed
    package.json is the tarball itself. Where they disagree, the tarball is what runs.
    """
    doc = load_json(lock_path)
    if not doc or "packages" not in doc:
        return {"lockfileVersion": doc.get("lockfileVersion") if doc else None, "entries": 0}

    out = {
        "lockfileVersion": doc.get("lockfileVersion"),
        "entries": 0,
        "lock_says_install_script": 0,
        "comparable": 0,
        "script_agree": 0,
        "script_lock_yes_tarball_no": 0,
        "script_lock_no_tarball_yes": 0,
        "license_present_in_lock": 0,
        "license_absent_in_lock": 0,
        "license_agree": 0,
        "license_lock_absent_tarball_present": 0,
        "license_conflict": 0,
        "license_conflict_examples": [],
        "not_installed": 0,
    }

    for path, ent in doc["packages"].items():
        if not path.startswith("node_modules/") or ent.get("link"):
            continue
        out["entries"] += 1
        lock_script = bool(ent.get("hasInstallScript"))
        if lock_script:
            out["lock_says_install_script"] += 1
        lock_lic = ent.get("license") if isinstance(ent.get("license"), str) else None
        if lock_lic is None:
            out["license_absent_in_lock"] += 1
        else:
            out["license_present_in_lock"] += 1

        pj = load_json(os.path.join(project_dir, path, "package.json"))
        if pj is None:
            out["not_installed"] += 1
            continue
        out["comparable"] += 1

        scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
        tarball_script = any(
            isinstance(scripts.get(k), str) and scripts[k].strip() for k in SCRIPT_KEYS
        )
        if lock_script == tarball_script:
            out["script_agree"] += 1
        elif lock_script:
            out["script_lock_yes_tarball_no"] += 1
        else:
            out["script_lock_no_tarball_yes"] += 1

        tarball_lic = norm_license(pj)
        if lock_lic == tarball_lic:
            out["license_agree"] += 1
        elif lock_lic is None:
            out["license_lock_absent_tarball_present"] += 1
            if len(out["license_conflict_examples"]) < 8:
                out["license_conflict_examples"].append(
                    {
                        "package": f"{pj.get('name')}@{pj.get('version')}",
                        "lock": None,
                        "tarball": tarball_lic,
                    }
                )
        else:
            out["license_conflict"] += 1
            if len(out["license_conflict_examples"]) < 8:
                out["license_conflict_examples"].append(
                    {
                        "package": f"{pj.get('name')}@{pj.get('version')}",
                        "lock": lock_lic,
                        "tarball": tarball_lic,
                    }
                )
    return out


def run_gate(project_dir, lockfile):
    """Worst case run: no base, so every package in the tree is treated as newly added."""
    cmd = [
        "node",
        os.path.join(ROOT, "bin", "install-gate.mjs"),
        "--cwd", project_dir,
        "--lockfile", lockfile,
        "--node-modules",
        "--min-age-days", "0",
        "--format", "json",
        "--quiet",
        "--json-out", "/dev/stdout",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        return {"error": proc.stderr.strip()[:500], "exit": proc.returncode}
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return {"error": "gate did not emit JSON", "exit": proc.returncode}
    rules = Counter(f["rule"] for f in data["findings"])
    return {
        "exit": proc.returncode,
        "added": len(data["added"]),
        "total": data["total"],
        "counts": data["counts"],
        "rules": dict(rules),
        "findings": [
            {
                "package": f["package"],
                "rule": f["rule"],
                "severity": f["severity"],
                "summary": f["summary"],
                "source": (f.get("evidence") or {}).get("source"),
                "class": (f.get("evidence") or {}).get("class"),
            }
            for f in data["findings"]
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default=os.environ.get("INSTALL_GATE_TREES"))
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "real_trees.json"))
    args = ap.parse_args()

    base = args.projects_dir or os.path.join(os.path.expanduser("~"), "Projects")
    if not os.path.isdir(base):
        sys.exit(
            f"no such directory: {base}\n"
            "Set INSTALL_GATE_TREES to a directory holding JavaScript projects that have both a "
            "lockfile and an installed node_modules."
        )

    dirs = sorted(
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d, "node_modules"))
    )
    if not dirs:
        sys.exit(f"{base} contains no project with a node_modules directory")

    trees = []
    for i, d in enumerate(dirs, 1):
        project_dir = os.path.join(base, d)
        label = f"tree-{i:02d}"
        t = measure_tree(project_dir, label)
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            if os.path.exists(os.path.join(project_dir, name)):
                t["lockfile_kind"] = name
                t["gate"] = run_gate(project_dir, name)
                break
        else:
            t["lockfile_kind"] = None
            t["gate"] = None
        trees.append(t)
        print(
            f"  {label}  {t['installed_packages']:5d} installed  "
            f"{t['installed_with_install_script']:3d} with install scripts  "
            f"{t['lockfile_kind']}",
            flush=True,
        )

    totals = {
        "trees": len(trees),
        "installed_packages": sum(t["installed_packages"] for t in trees),
        "installed_with_install_script": sum(t["installed_with_install_script"] for t in trees),
        "script_kinds": dict(sum((Counter(t["script_kinds"]) for t in trees), Counter())),
        "licenses": dict(sum((Counter(t["licenses"]) for t in trees), Counter())),
        "distinct_script_packages": sorted(
            {p["package"].rsplit("@", 1)[0] for t in trees for p in t["script_packages"]}
        ),
    }
    lock_totals = Counter()
    lock_trees = 0
    conflicts = []
    for t in trees:
        lf = t.get("lockfile")
        if not lf or "entries" not in lf or lf["entries"] == 0:
            continue
        lock_trees += 1
        for k, v in lf.items():
            if isinstance(v, int):
                lock_totals[k] += v
        conflicts.extend(lf.get("license_conflict_examples", []))
    totals["lockfile_vs_tarball"] = dict(lock_totals)
    totals["lockfile_vs_tarball"]["npm_trees"] = lock_trees
    totals["license_conflict_examples"] = conflicts[:20]

    gate_totals = Counter()
    rule_totals = Counter()
    for t in trees:
        g = t.get("gate")
        if not g or "counts" not in g:
            continue
        for k, v in g["counts"].items():
            gate_totals[k] += v
        for k, v in g["rules"].items():
            rule_totals[k] += v
    totals["gate"] = {"severities": dict(gate_totals), "rules": dict(rule_totals)}

    out = {"totals": totals, "trees": trees}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"\nwrote {os.path.relpath(args.out, ROOT)}")
    print(json.dumps(totals["lockfile_vs_tarball"], indent=2))
    print(json.dumps(totals["gate"], indent=2))


if __name__ == "__main__":
    main()
