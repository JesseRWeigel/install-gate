#!/usr/bin/env python3
"""Hand-audit every finding the gate produced on real trees.

A gate is only worth running if its findings are true. "The rules are safe" is an assertion.
This is the measurement behind it.

A finding is counted as a FALSE POSITIVE when the claim it makes is not true of the package:

  * install-script: the package does not in fact declare preinstall, install or postinstall
  * license-class: the license string is not what the finding says, or the classification does
    not match the actual terms of that license
  * new-package: the package was not in fact first published within the window
  * an unknown: a source that WAS consulted did in fact carry the fact

Being factually correct is not the same as being worth a reviewer's time, so a second count is
reported: findings that are true but that a team would accept every single time. A gate full of
those still gets switched off, so hiding the number would defeat the purpose.

The mechanical half of the audit runs here: every install-script finding is re-checked by
opening the installed package.json directly, and every license finding by reading the license
string directly. The judgement half, whether a classification matches the real terms of the
license, is recorded by hand in results/hand_check.json and cross-referenced.

Usage:
    python3 scripts/audit_findings.py [--projects-dir DIR]
"""

import argparse
import json
import os
import re
import sys

SCRIPT_KEYS = ("preinstall", "install", "postinstall")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def normalise_reason(reason):
    """Collapse a per-package reason to the reason itself.

    "node_modules/left-pad/package.json declares no license field" is one reason with a package
    name in it, not one reason per package, and the audit records a verdict per reason.
    """
    if not reason:
        return reason
    return re.sub(r"^\S*node_modules/\S+/package\.json", "an installed package.json", reason)


def index_installed(root):
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
        lic = doc.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        out[key] = {
            "scripts": {
                k: scripts[k] for k in SCRIPT_KEYS
                if isinstance(scripts.get(k), str) and scripts[k].strip()
            },
            "license": lic if isinstance(lic, str) else None,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default=os.environ.get("INSTALL_GATE_TREES"))
    ap.add_argument("--trees-json", default=os.path.join(ROOT, "results", "real_trees.json"))
    ap.add_argument("--hand-check", default=os.path.join(ROOT, "results", "hand_check.json"))
    ap.add_argument("--registry-confirmations",
                    default=os.path.join(ROOT, "results", "registry_confirmations.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "fp_audit.json"))
    args = ap.parse_args()

    base = args.projects_dir or os.path.join(os.path.expanduser("~"), "Projects")
    if not os.path.isdir(base):
        sys.exit("no such directory: %s. Set INSTALL_GATE_TREES." % base)

    with open(args.trees_json, encoding="utf-8") as fh:
        trees = json.load(fh)

    # One index across every tree on the machine. A package flagged in one tree may be installed
    # in another, and the tarball is the same tarball either way.
    installed = {}
    for d in sorted(os.listdir(base)):
        if os.path.isdir(os.path.join(base, d, "node_modules")):
            for k, v in index_installed(os.path.join(base, d)).items():
                installed.setdefault(k, v)

    # Packages declared in a lockfile but not installed here, for example a darwin-only
    # optional dependency on a Linux machine, cannot be checked against a local tarball. Their
    # published metadata was fetched once and committed, so the audit still reaches a verdict
    # rather than leaving them permanently unconfirmed.
    registry_confirmed = {}
    if os.path.exists(args.registry_confirmations):
        with open(args.registry_confirmations, encoding="utf-8") as fh:
            registry_confirmed = json.load(fh).get("packages", {})

    with open(args.hand_check, encoding="utf-8") as fh:
        hand = json.load(fh)
    hand_by_key = {h["subject"]: h for h in hand["checks"]}

    distinct = {}
    total_findings = 0
    for t in trees["trees"]:
        gate = t.get("gate") or {}
        for f in gate.get("findings", []):
            total_findings += 1
            distinct.setdefault((f["package"], f["rule"]), f)

    audited = []
    for (pkg, rule), f in sorted(distinct.items()):
        row = {"package": pkg, "rule": rule, "severity": f["severity"],
               "summary": f["summary"], "source": f.get("source")}

        if rule == "install-script":
            inst = installed.get(pkg)
            if inst is None:
                conf = registry_confirmed.get(pkg)
                if conf is None:
                    # Neither confirmed nor refuted. Counting it as correct would be assuming
                    # the answer the audit exists to establish.
                    row["verdict"] = "unconfirmed"
                    row["why"] = ("not installed on this machine and no registry confirmation "
                                  "is recorded, so the tarball cannot be read")
                elif conf.get("install_scripts"):
                    row["verdict"] = "true-positive"
                    row["why"] = ("registry packument declares "
                                  + ", ".join(sorted(conf["install_scripts"])))
                    row["scripts"] = conf["install_scripts"]
                    row["confirmed_via"] = "registry"
                else:
                    row["verdict"] = "false-positive"
                    row["why"] = "registry packument declares no install lifecycle script"
                    row["confirmed_via"] = "registry"
            elif inst["scripts"]:
                row["verdict"] = "true-positive"
                row["why"] = "tarball declares " + ", ".join(sorted(inst["scripts"]))
                row["scripts"] = inst["scripts"]
            else:
                row["verdict"] = "false-positive"
                row["why"] = "tarball declares no install lifecycle script"

        elif rule in ("license-class", "license-unparsed"):
            claimed = f["summary"].split('"')[1] if '"' in f["summary"] else None
            members = f.get("packages") or [pkg]
            real = None
            for m in members:
                inst = installed.get(m)
                if inst is not None:
                    real = inst["license"]
                    break
            row["claimed_license"] = claimed
            row["license_in_tarball"] = real
            row["class"] = f.get("class")
            row["members"] = len(members)
            if real is not None and claimed is not None and real != claimed:
                row["verdict"] = "false-positive"
                row["why"] = "gate read %r, tarball says %r" % (claimed, real)
            else:
                hc = hand_by_key.get(claimed)
                if hc is None:
                    row["verdict"] = "unaudited"
                    row["why"] = "no hand check recorded for this license string"
                elif hc["classification_correct"]:
                    row["verdict"] = "true-positive"
                    row["why"] = hc["note"]
                    row["actionable"] = hc.get("actionable", True)
                else:
                    row["verdict"] = "false-positive"
                    row["why"] = hc["note"]

        elif rule.endswith("-unknown"):
            subject = normalise_reason(f.get("source"))
            row["reason"] = subject
            hc = hand_by_key.get(subject)
            if hc is None:
                row["verdict"] = "unaudited"
                row["why"] = "no hand check recorded for this reason string"
            elif hc["classification_correct"]:
                row["verdict"] = "true-positive"
                row["why"] = hc["note"]
                row["actionable"] = hc.get("actionable", True)
            else:
                row["verdict"] = "false-positive"
                row["why"] = hc["note"]
        else:
            row["verdict"] = "unaudited"
            row["why"] = "rule not covered by the audit"

        audited.append(row)

    counts = {}
    for r in audited:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    judged = counts.get("true-positive", 0) + counts.get("false-positive", 0)
    fp_rate = (counts.get("false-positive", 0) / judged) if judged else None

    by_rule = {}
    for r in audited:
        b = by_rule.setdefault(r["rule"], {})
        b[r["verdict"]] = b.get(r["verdict"], 0) + 1

    low_value = [r for r in audited if r.get("actionable") is False]

    out = {
        "total_findings_across_trees": total_findings,
        "distinct_findings_audited": len(audited),
        "verdicts": counts,
        "judged": judged,
        "false_positive_rate": fp_rate,
        "by_rule": by_rule,
        "correct_but_low_value": len(low_value),
        "correct_but_low_value_subjects": sorted(
            {r.get("claimed_license") or r["rule"] for r in low_value}
        ),
        "findings": audited,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("distinct findings audited: %d (from %d across all trees)"
          % (len(audited), total_findings))
    for k in sorted(counts):
        print("  %-22s %d" % (k, counts[k]))
    if fp_rate is not None:
        print("false-positive rate: %d/%d = %.1f%%"
              % (counts.get("false-positive", 0), judged, 100 * fp_rate))
    print("correct but low value: %d" % len(low_value))
    print("wrote " + os.path.relpath(args.out, ROOT))

    if counts.get("unaudited"):
        print("\n%d findings have no hand check. Add them to results/hand_check.json."
              % counts["unaudited"])
        for r in audited:
            if r["verdict"] == "unaudited":
                print("  %s [%s] %s" % (r["package"], r["rule"], r.get("claimed_license")
                                        or r.get("source")))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
