#!/usr/bin/env python3
"""Measure how noisy the gate is on real lockfile changes.

A gate that produces hundreds of findings gets switched off, and then what it would have caught
does not matter. The number that decides this is not how many findings a whole tree produces.
It is how many a single pull request produces, because that is what a reviewer sees.

So this replays real history: every commit in every repo that touched package-lock.json is run
through the gate with the parent commit's lockfile as the base, which is exactly the comparison
the Action makes on a pull request. It reports the distribution, not just the mean, because a
tool with a good average and a 300-finding tail still gets switched off on the day of the tail.

node_modules is deliberately not consulted here. A historical lockfile does not match the
currently installed tree, and more to the point the pre-install lockfile diff is the mode a pull
request check actually runs in.

Usage:
    python3 scripts/measure_pr_noise.py [--projects-dir DIR] [--out results/pr_noise.json]
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOCKNAMES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo, *args], capture_output=True, text=True, check=False
    )


def show(repo, ref, path):
    p = git(repo, "show", f"{ref}:{path}")
    return p.stdout if p.returncode == 0 else None


def run_gate(head_file, base_file, lockname):
    """Run the gate on two files, which is what --base does with a path."""
    with tempfile.TemporaryDirectory() as td:
        head_path = os.path.join(td, lockname)
        with open(head_path, "w", encoding="utf-8") as fh:
            fh.write(head_file)
        args = ["--cwd", td, "--lockfile", lockname, "--min-age-days", "0",
                "--format", "json", "--quiet", "--json-out", "/dev/stdout"]
        if base_file is not None:
            base_path = os.path.join(td, f"base-{lockname}")
            with open(base_path, "w", encoding="utf-8") as fh:
                fh.write(base_file)
            args += ["--base", f"base-{lockname}"]
        proc = subprocess.run(
            ["node", os.path.join(ROOT, "bin", "install-gate.mjs"), *args],
            capture_output=True, text=True,
        )
        if proc.returncode not in (0, 1):
            return {"error": proc.stderr.strip()[:300], "exit": proc.returncode}
        try:
            return {"exit": proc.returncode, **json.loads(proc.stdout)}
        except ValueError:
            return {"error": "no JSON from gate", "exit": proc.returncode}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default=os.environ.get("INSTALL_GATE_TREES"))
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "pr_noise.json"))
    ap.add_argument("--max-commits", type=int, default=60)
    args = ap.parse_args()

    base = args.projects_dir or os.path.join(os.path.expanduser("~"), "Projects")
    if not os.path.isdir(base):
        sys.exit(
            f"no such directory: {base}\n"
            "Set INSTALL_GATE_TREES to a directory of JavaScript projects with git history."
        )

    repos = sorted(
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d, ".git"))
        and any(os.path.exists(os.path.join(base, d, n)) for n in LOCKNAMES)
    )

    changes = []
    per_repo = []
    for i, name in enumerate(repos, 1):
        repo = os.path.join(base, name)
        label = f"repo-{i:02d}"
        for lockname in LOCKNAMES:
            if not os.path.exists(os.path.join(repo, lockname)):
                continue
            log = git(repo, "log", "--format=%H", f"-{args.max_commits}", "--", lockname)
            commits = [c for c in log.stdout.split() if c]
            got = 0
            for sha in commits:
                head_text = show(repo, sha, lockname)
                if head_text is None:
                    continue
                base_text = show(repo, f"{sha}^", lockname)
                res = run_gate(head_text, base_text, lockname)
                if "error" in res:
                    continue
                counts = res["counts"]
                changes.append({
                    "repo": label,
                    "lockfile": lockname,
                    "first_lockfile_commit": base_text is None,
                    "added": len(res["added"]),
                    "block": counts["block"],
                    "review": counts["review"],
                    "note": counts["note"],
                    "findings": counts["block"] + counts["review"] + counts["note"],
                    "rules": dict(Counter(f["rule"] for f in res["findings"])),
                    "exit": res["exit"],
                })
                got += 1
            per_repo.append({"repo": label, "lockfile": lockname, "commits_replayed": got})
            print(f"  {label} {lockname}: {got} lockfile commits replayed", flush=True)
            break

    if not changes:
        sys.exit("no lockfile commits found to replay")

    # The first commit that introduced a lockfile has no base, so every package counts as added.
    # It is a real event but it is not a pull request adding a dependency, and mixing it into the
    # distribution would flatter or damn the tool for the wrong reason. Both are reported.
    ordinary = [c for c in changes if not c["first_lockfile_commit"]]
    initial = [c for c in changes if c["first_lockfile_commit"]]

    def dist(rows, key):
        vals = sorted(r[key] for r in rows)
        if not vals:
            return None
        return {
            "n": len(vals),
            "zero": sum(1 for v in vals if v == 0),
            "median": statistics.median(vals),
            "mean": round(statistics.mean(vals), 2),
            "p90": vals[min(len(vals) - 1, int(0.9 * len(vals)))],
            "max": max(vals),
        }

    rules = Counter()
    for c in ordinary:
        rules.update(c["rules"])

    out = {
        "repos": len(per_repo),
        "lockfile_commits_replayed": len(changes),
        "ordinary_changes": len(ordinary),
        "initial_lockfile_commits": len(initial),
        "ordinary": {
            "added_packages": dist(ordinary, "added"),
            "findings": dist(ordinary, "findings"),
            "blocking": dist(ordinary, "block"),
            "review": dist(ordinary, "review"),
            "silent_changes": sum(1 for c in ordinary if c["findings"] == 0),
            "changes_that_would_block": sum(1 for c in ordinary if c["block"] > 0),
            "rules": dict(rules),
        },
        "initial": {
            "added_packages": dist(initial, "added"),
            "findings": dist(initial, "findings"),
        },
        "per_repo": per_repo,
        "changes": changes,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"\nwrote {os.path.relpath(args.out, ROOT)}")
    print(json.dumps({k: out[k] for k in ("repos", "lockfile_commits_replayed",
                                          "ordinary_changes", "initial_lockfile_commits")},
                     indent=2))
    print(json.dumps(out["ordinary"], indent=2))


if __name__ == "__main__":
    main()
