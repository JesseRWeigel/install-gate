#!/usr/bin/env python3
"""Build docs/index.html from the committed results.

Every number on the page comes from results/. Nothing is typed in. The page is rebuilt in
verify.sh and compared byte for byte against the committed copy, so a stale number on the site
fails the build rather than sitting there being wrong.
"""

import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "results")


def load(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as fh:
        return json.load(fh)


def esc(x):
    return html.escape(str(x))


def stat(value, label, note=""):
    note_html = f'<div class="note">{esc(note)}</div>' if note else ""
    return (
        f'<div class="stat"><div class="v">{esc(value)}</div>'
        f'<div class="l">{esc(label)}</div>{note_html}</div>'
    )


def main():
    trees = load("real_trees.json")
    noise = load("pr_noise.json")
    audit = load("fp_audit.json")

    t = trees["totals"]
    lv = t["lockfile_vs_tarball"]
    ordinary = noise["ordinary"]

    licenses = sorted(t["licenses"].items(), key=lambda kv: -kv[1])
    top_licenses = licenses[:12]
    total_licensed = sum(t["licenses"].values())

    script_rows = "".join(
        f"<tr><td><code>{esc(name)}</code></td></tr>" for name in t["distinct_script_packages"]
    )

    license_rows = "".join(
        f"<tr><td><code>{esc(k if k != 'None' else 'not declared')}</code></td>"
        f"<td class=\"num\">{v}</td>"
        f"<td class=\"num\">{100 * v / total_licensed:.2f}%</td></tr>"
        for k, v in top_licenses
    )

    per_tree_rows = "".join(
        f"<tr><td>{esc(tr['label'])}</td>"
        f"<td>{esc(tr['lockfile_kind'] or 'none')}</td>"
        f"<td class=\"num\">{tr['installed_packages']}</td>"
        f"<td class=\"num\">{tr['installed_with_install_script']}</td>"
        f"<td class=\"num\">{(tr.get('gate') or {}).get('counts', {}).get('block', 0)}</td>"
        f"<td class=\"num\">{(tr.get('gate') or {}).get('counts', {}).get('review', 0)}</td>"
        "</tr>"
        for tr in trees["trees"]
    )

    verdict_rows = "".join(
        f"<tr><td>{esc(k)}</td><td class=\"num\">{v}</td></tr>"
        for k, v in sorted(audit["verdicts"].items())
    )

    rule_rows = "".join(
        f"<tr><td><code>{esc(rule)}</code></td>"
        + "".join(
            f"<td class=\"num\">{counts.get(v, 0)}</td>"
            for v in ("true-positive", "false-positive", "unconfirmed")
        )
        + "</tr>"
        for rule, counts in sorted(audit["by_rule"].items())
    )

    pct_scripts = 100 * t["installed_with_install_script"] / t["installed_packages"]
    fp_rate = audit["false_positive_rate"]
    fp_display = "0%" if fp_rate == 0 else f"{100 * fp_rate:.1f}%"

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>install-gate, measured</title>
<style>
  :root {{
    --bg: #fbfaf8; --fg: #1c1b19; --muted: #6b6862; --line: #e0ddd6;
    --card: #ffffff; --accent: #b4531f; --ok: #2f6b41;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #17161a; --fg: #eae7e1; --muted: #9c968c; --line: #322f36;
      --card: #201e24; --accent: #e2884f; --ok: #7fbf95;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg: #17161a; --fg: #eae7e1; --muted: #9c968c; --line: #322f36;
    --card: #201e24; --accent: #e2884f; --ok: #7fbf95;
  }}
  :root[data-theme="light"] {{
    --bg: #fbfaf8; --fg: #1c1b19; --muted: #6b6862; --line: #e0ddd6;
    --card: #ffffff; --accent: #b4531f; --ok: #2f6b41;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--fg);
    font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width: 62rem; margin: 0 auto; padding: 3rem 1.25rem 5rem; }}
  h1 {{ font-size: clamp(1.8rem, 5vw, 2.6rem); line-height: 1.15; margin: 0 0 .5rem; letter-spacing: -.02em; }}
  h2 {{ font-size: 1.3rem; margin: 3rem 0 .75rem; letter-spacing: -.01em; }}
  h3 {{ font-size: 1.02rem; margin: 2rem 0 .5rem; color: var(--muted); font-weight: 600; }}
  p {{ margin: 0 0 1rem; max-width: 46rem; }}
  .lede {{ font-size: 1.1rem; color: var(--muted); max-width: 44rem; }}
  a {{ color: var(--accent); }}
  code {{
    font: .88em ui-monospace, SFMono-Regular, Menlo, monospace;
    background: color-mix(in srgb, var(--fg) 7%, transparent);
    padding: .1em .35em; border-radius: 4px;
  }}
  .stats {{ display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); margin: 1.5rem 0 2rem; }}
  .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 1rem; min-width: 0; }}
  .stat .v {{ font-size: 1.7rem; font-weight: 640; letter-spacing: -.02em; overflow-wrap: anywhere; }}
  .stat .l {{ color: var(--muted); font-size: .84rem; margin-top: .15rem; }}
  .stat .note {{ color: var(--muted); font-size: .76rem; margin-top: .4rem; opacity: .85; }}
  .scroll {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--card); }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--line); white-space: nowrap; }}
  th {{ color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
  tr:last-child td {{ border-bottom: 0; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .callout {{ border-left: 3px solid var(--accent); padding: .1rem 0 .1rem 1rem; margin: 1.5rem 0; color: var(--muted); }}
  .callout strong {{ color: var(--fg); }}
  footer {{ margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .88rem; }}
</style>
</head>
<body>
<div class="wrap">

<h1>install-gate</h1>
<p class="lede">A pre-merge check that fails when a dependency change adds a package with an
install script, a license outside your allowlist, or a name first published days ago. These are
the numbers it produced on {t["trees"]} real dependency trees.</p>

<div class="stats">
  {stat(f"{t['installed_packages']:,}", "packages measured", f"across {t['trees']} real trees")}
  {stat(t["installed_with_install_script"], "declare an install script", f"{pct_scripts:.2f}% of them")}
  {stat(fp_display, "false-positive rate", f"{audit['judged']} findings hand-checked")}
  {stat(ordinary["findings"]["median"], "findings on a median change", f"mean {ordinary['findings']['mean']}, worst {ordinary['findings']['max']}")}
</div>

<h2>What actually runs code at install time</h2>
<p>Of {t["installed_packages"]:,} installed packages, {t["installed_with_install_script"]}
declare <code>preinstall</code>, <code>install</code> or <code>postinstall</code>. That is
{pct_scripts:.2f}%, and they reduce to {len(t["distinct_script_packages"])} distinct package
names, because the same handful appears in tree after tree.</p>

<div class="scroll">
<table>
<thead><tr><th>every package name on these trees that runs an install script</th></tr></thead>
<tbody>{script_rows}</tbody>
</table>
</div>

<h3>Which lifecycle hook</h3>
<div class="scroll">
<table>
<thead><tr><th>hook</th><th class="num">occurrences</th></tr></thead>
<tbody>{"".join(f'<tr><td><code>{esc(k)}</code></td><td class="num">{v}</td></tr>' for k, v in sorted(t["script_kinds"].items(), key=lambda kv: -kv[1]))}</tbody>
</table>
</div>

<h2>What licenses actually appear</h2>
<p>{total_licensed:,} declarations, {len(t["licenses"])} distinct strings. The long tail is
where the work is: dual licenses, non-SPDX strings, and packages that declare nothing.</p>

<div class="scroll">
<table>
<thead><tr><th>license string</th><th class="num">packages</th><th class="num">share</th></tr></thead>
<tbody>{license_rows}</tbody>
</table>
</div>

<h2>What a lockfile can and cannot tell you</h2>
<p>An npm lockfile version 2 or 3 records <code>hasInstallScript</code> and <code>license</code>
per entry. Comparing those claims against the installed tarball's own <code>package.json</code>,
which is the code that actually runs:</p>

<div class="stats">
  {stat(f"{lv['comparable']:,}", "entries comparable", "installed, so both sources exist")}
  {stat(lv["script_agree"], "agree on install scripts", "no disagreement in either direction")}
  {stat(lv["license_lock_absent_tarball_present"], "licenses the lockfile missed", "present in the tarball, absent from the lockfile")}
  {stat(f"{lv['not_installed']:,}", "entries not installed here", "other platforms, so unverifiable locally")}
</div>

<div class="callout">
<p><strong>The window of trust ends at the lockfile.</strong> The integrity hash pins one exact
tarball, so what the lockfile says about that version stays true. It says nothing about the next
version. A package can add a <code>postinstall</code> in a patch release, and the moment your
range resolves to it you have new code running at install time that no previous review saw.</p>
</div>

<h2>Noise, measured on real history</h2>
<p>{noise["lockfile_commits_replayed"]} real lockfile commits across {noise["repos"]} repositories
were replayed with the parent commit as the base, which is exactly the comparison the Action
makes on a pull request.</p>

<div class="stats">
  {stat(ordinary["findings"]["median"], "median findings per change")}
  {stat(ordinary["blocking"]["max"], "worst blocking count", f"of {ordinary['findings']['n']} changes")}
  {stat(ordinary["silent_changes"], "changes with no findings", f"of {ordinary['findings']['n']}")}
  {stat(ordinary["changes_that_would_block"], "changes that would block", "the rest merge untouched")}
</div>

<h2>Are the findings true</h2>
<p>{audit["distinct_findings_audited"]} distinct findings were checked one at a time by opening
the package's own <code>package.json</code> and its <code>LICENSE</code> file, or by fetching the
published metadata where the package is not installable on this platform.</p>

<div class="scroll">
<table>
<thead><tr><th>verdict</th><th class="num">findings</th></tr></thead>
<tbody>{verdict_rows}</tbody>
</table>
</div>

<h3>By rule</h3>
<div class="scroll">
<table>
<thead><tr><th>rule</th><th class="num">true</th><th class="num">false</th><th class="num">unconfirmed</th></tr></thead>
<tbody>{rule_rows}</tbody>
</table>
</div>

<p>{audit["correct_but_low_value"]} finding is correct but low value: a font shipped under
<code>SIL OPEN FONT LICENSE</code>, which is a real permissive license written as a string SPDX
does not define. The gate is right that it cannot classify the string by identifier, and a team
would accept it every time.</p>

<h2>Per tree</h2>
<div class="scroll">
<table>
<thead><tr><th>tree</th><th>lockfile</th><th class="num">packages</th><th class="num">install scripts</th><th class="num">blocking</th><th class="num">review</th></tr></thead>
<tbody>{per_tree_rows}</tbody>
</table>
</div>
<p>Blocking and review counts here are the worst case, a first run where every package in the
tree counts as newly added. A pull request adds a handful.</p>

<footer>
Task DEVT-029 from the 1000-task catalog.
<a href="https://github.com/JesseRWeigel/install-gate">Source on GitHub</a>. MIT licensed.
Every number on this page is generated from <code>results/</code> by
<code>scripts/build_docs.py</code> and checked byte for byte in <code>scripts/verify.sh</code>.
</footer>

</div>
</body>
</html>
"""
    out = os.path.join(ROOT, "docs", "index.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"wrote {os.path.relpath(out, ROOT)} ({len(page)} bytes)")
    print(f"  {t['installed_packages']} packages, {t['installed_with_install_script']} with "
          f"install scripts, false-positive rate {fp_display}")


if __name__ == "__main__":
    main()
