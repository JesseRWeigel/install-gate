# install-gate

A pre-merge check that fails when a dependency change **adds** a package with an install script,
a license outside your allowlist, or a name first published days ago, and prints the
justification line a reviewer needs.

**[The measured numbers](https://jesserweigel.github.io/install-gate/)**

It only looks at what a change adds. A repository with a thousand existing dependencies gets zero
findings until somebody adds the thousand-and-first, which is the difference between a check
people keep and a check people delete in week two.

## Use

As a GitHub Action:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- run: npm ci
- uses: JesseRWeigel/install-gate@main
  with:
    base-ref: ${{ github.event.pull_request.base.sha }}
    node-modules: "true"
```

Or as a CLI, with no dependencies beyond Node 18:

```bash
node bin/install-gate.mjs --base main --node-modules
```

Exit codes are the product. **0** means no finding at or above `--fail-on`. **1** means at least
one. **2** means the gate could not run, which is deliberately not 0, because a green check on a
run that never happened is worse than no check.

## What it found on real trees

Measured on **14** real dependency trees, **5,689** installed packages:

| | |
|---|---|
| packages declaring `preinstall`, `install` or `postinstall` | **36**, which is 0.63% |
| distinct package names among them | **10** |
| distinct license strings | 26 |
| lockfile entries compared against their installed tarball | 4,164 |

The ten names that run code at install time on these trees: `better-sqlite3`, `canvas`,
`core-js`, `cypress`, `esbuild`, `msedge-tts`, `msw`, `protobufjs`, `sharp`, `unrs-resolver`.
Nine of them build or fetch a native binary. `msedge-tts` runs `npx only-allow pnpm`, which
downloads and executes a package during your install in order to complain about your package
manager.

`postinstall` accounts for 29 of the 36, `install` for 6, `preinstall` for 1.

Licenses are overwhelmingly boring: MIT 4,760, ISC 299, Apache-2.0 279, BSD-2-Clause 96,
BSD-3-Clause 84. The work is in the tail. `(MPL-2.0 OR Apache-2.0)`, `(MIT or Apache-2.0)` with a
lowercase operator, `Apache-2.0 AND LGPL-3.0-or-later AND MIT`, `SIL OPEN FONT LICENSE`, `BSD`
with no version, and 12 packages that declare nothing at all.

## What the gate cannot see

This is the part that decides whether the check is worth anything, so it comes before the
features.

**A lockfile describes one tarball, and the window closes at the next release.** An npm
`package-lock.json` pins an integrity hash, so the tarball behind a given version cannot change
under you, and what the lockfile records about that version stays true. It says nothing at all
about the next version. A package with no install script today can publish one in a patch
release, and the moment your range resolves to it there is new code running at install time on
every machine in your team. The gate re-examines a package on every version change for exactly
this reason, and that is the whole of the protection. **There is no ongoing guarantee, only a
per-version one.**

**Registry metadata and the published tarball are different things.** On these trees the npm
lockfile's `hasInstallScript` agreed with the installed tarball on all **4,164** entries that
could be compared, in both directions. Licenses did not: **6** packages have no license in the
lockfile while their tarball declares MIT, among them `passport-local`, `passport-strategy` and
`to-array`. The gate treats the installed tarball as authoritative and reports a
`source-disagreement` finding when the two differ, rather than silently preferring one.

**915 of 5,079 lockfile entries were not installed here at all**, because they are for other
platforms. Their facts come from lockfile metadata alone and cannot be checked against a tarball
on this machine.

**pnpm and yarn lockfiles carry neither install-script nor license information.** pnpm
lockfileVersion 9 dropped `requiresBuild`, and yarn v1 never had anything equivalent. Checked
against real files of both kinds: neither contains the data. On those projects the gate reports
unknown until you run it after an install with `--node-modules`.

**An allowlist entry with no version accepts every future release of that package**, including
one published by whoever next compromises the maintainer account. The gate says so in the
acceptance line it prints, and `versions: [...]` narrows it.

**It never reads license text.** A package with no `license` field but a `LICENSE.md` full of MIT
text is reported as having no declared license, with the filename named so a human can open it.
Identifying a license from prose is a different problem, and guessing at it would be the
confident wrong answer this whole tool is shaped against.

**It does not sandbox anything, detect obfuscation, or judge whether a script is malicious.** It
tells you a script exists and what its command line is.

## Noise, which is what actually kills a check like this

A gate nobody keeps enabled protects nobody, so this was measured rather than hoped for. **79**
real lockfile commits across **13** repositories were replayed with the parent commit as the
base, which is exactly the comparison the Action makes on a pull request. **67** of those are
ordinary changes and 12 are the commit that first introduced a lockfile.

Across the 67 ordinary changes:

| | |
|---|---|
| median findings | **2** |
| mean findings | 1.37 |
| worst case | 7 |
| changes producing nothing at all | 24 |
| changes that would have blocked the merge | **7** |
| worst blocking count on any one change | 5 |

The first version was far worse, and the measurement is what showed it. It produced a **mean of
73 findings and a worst case of 1,392**. Almost all of that was one sentence repeated: a pnpm
change adding 881 packages emitted 881 identical copies of "pnpm-lock.yaml records no
install-script flag", which is a fact about the file format rather than 881 facts about packages.

Two changes fixed it, and neither hides anything:

1. **Findings that represent one decision are reported as one finding.** Unknowns group by
   reason, license findings group by the exact license string. A single MPL-2.0 dependency used
   to arrive as 64 lines, because `lightningcss` ships one prebuilt binary per platform and each
   is its own package. It is now 3, one per distinct license string, listing the members.
   Install-script findings deliberately do not group, because each is a separate piece of code
   that will run.
2. **The installed tree is indexed rather than guessed at.** Resolving packages by guessing their
   path left 957 of 5,689 unresolved, and every one became an unknown a reviewer had to read.
   Walking the tree once, including `node_modules/.pnpm`, brought that to 2.

Blocking counts did not move through either fix. Mean blocking stayed at 0.28.

## Are the findings true

**51 distinct findings, 0 false positives.**

Every finding the gate produced across all 14 trees was checked by hand. A finding counts as a
false positive when its claim is not true of the package: it says a package declares an install
script and the package does not, or it reports a license the package does not carry, or it says a
fact is unavailable when a source it consulted did carry it.

| rule | findings | true | false |
|---|---|---|---|
| `install-script` | 24 | 24 | 0 |
| `license-class` | 11 | 11 | 0 |
| `license-unknown` | 13 | 13 | 0 |
| `install-script-unknown` | 2 | 2 | 0 |
| `license-unparsed` | 1 | 1 | 0 |

Method: for install-script findings, the installed `package.json` was opened and the script read.
21 were confirmed that way. The remaining 3 are `fsevents@2.3.2`, `fsevents@2.3.3` and
`canvas@2.11.2`, which are darwin-only or unbuilt on this machine, so their published metadata
was fetched from registry.npmjs.org and committed to `results/registry_confirmations.json`. All
three declare `install: node-gyp rebuild` or the node-pre-gyp equivalent.

For license findings, the license string was re-read from the tarball and the classification
checked against the actual terms. Those verdicts are written down one by one in
`results/hand_check.json` with the reasoning, so you can disagree with any of them.

**One finding is correct but low value**, and counting it matters more than hiding it. `geist`
declares `SIL OPEN FONT LICENSE`, which genuinely is not an SPDX expression, so the gate refuses
to classify it by identifier. The file in the package is the SIL Open Font License 1.1, which is
permissive. A team would accept this every single time, and a gate full of findings like it gets
switched off even though every one of them is true.

The classification rules a naive version gets wrong, all present in real data here:

- `LGPL-3.0-or-later` contains the substring `GPL` and is weak copyleft, not strong.
- `(MPL-2.0 OR Apache-2.0)` contains `MPL` and is permissive, because you choose the branch.
- `Apache-2.0 AND LGPL-3.0-or-later` starts with a permissive identifier and is weak copyleft,
  because `AND` means every obligation applies at once.
- `(MIT or Apache-2.0)` uses a lowercase operator SPDX does not allow, and real packages publish
  it, so refusing to parse it would misreport a permissive package.

## Sources, and what each one is worth

For every package the gate reports three facts, and each carries where it came from and whether
it is known at all. An unavailable fact is never rendered as a clean one.

| source | install scripts | license | first publish |
|---|---|---|---|
| npm lockfile v2 or v3 | yes, `hasInstallScript` | yes | no |
| npm lockfile v1 | no | no | no |
| pnpm lockfile v9 | no | no | no |
| yarn lockfile v1 | no | no | no |
| installed `node_modules` | yes, authoritative | yes | no |
| registry, with `--registry` | yes | yes | yes |

The registry serves two different documents and they carry install-script information in
different places, which was checked against registry.npmjs.org rather than assumed. The full
packument mirrors each published `package.json`, so it has `scripts` and no `hasInstallScript`
field at all. The abbreviated form has `hasInstallScript` and no `scripts`. Reading the wrong one
reports "no install script" for `fsevents`, which has had one for years.

## Configuration

`.install-gate.json`, all fields optional:

```json
{
  "allowInstallScripts": [
    { "name": "esbuild", "versions": ["0.25.0"], "reason": "builds its platform binary" }
  ],
  "licenseClasses": { "weak-copyleft": "review", "strong-copyleft": "block" },
  "allowLicenses": ["OFL-1.1"],
  "minAgeDays": 14,
  "onUnknown": "review"
}
```

Severities are `allow`, `note`, `review` and `block`. `--fail-on` decides which of them stops the
merge, and it defaults to `block`.

## Verification

```bash
bash scripts/verify.sh
```

Eleven layers, 32 checks, **39 unit tests**. The ones doing real work:

- **Every positive test is paired with a negative control.** A gate that flags everything scores
  perfectly on unsafe inputs, so the safe ones carry the weight: an unchanged lockfile, an
  already-present risky package, an allowlisted one, a permissive dual license containing the
  string `MPL`, an old package under the age rule, and a two-package MIT tree that must produce
  literally nothing. `verify.sh` fails if the count of them drops below 10.
- **The exit code is tested as the product it is**, including exit 2 on a run that could not
  complete, with a control proving the same directory exits 0 when run correctly.
- **An independent Python re-derivation** of every fact and every blocking finding, run against
  all 14 real trees as well as the fixtures. It shares no code with the gate, which `verify.sh`
  proves with `ast`: only stdlib imports, no `subprocess`, no `exec`, and no string constant
  naming a module of the implementation. Its own control is a copy of the gate with its license
  classifier corrupted, which the checker must reject.
- **Seven sabotages, each proved to have applied and proved to have changed the output** before
  its result counts. Two of them initially changed nothing and were reported as proving nothing,
  which is exactly what that check is for: `unknown-becomes-clean` never ran because no fixture
  had an unknown fact, and `license-by-substring` never fired because no fixture contained an
  LGPL package. Both fixtures were extended.
- **`action.yml` is parsed and cross-checked against the code**: every input reaches the step,
  every environment variable the entry script reads is set, and every declared output is written
  to `GITHUB_OUTPUT` by something. Its control misspells `base-ref` as `base_ref` and must fail.
  This caught a real mismatch where four declared outputs were written under names that did not
  exist.
- **The README is checked against `results/`**, including the unit test count in this sentence.

The real-tree layers need dependency trees. Set `INSTALL_GATE_TREES` to a directory of JavaScript
projects that have both a lockfile and an installed `node_modules`. Without it those layers
**fail** rather than skip, because a skipped check reports the same green as one that ran.

## What is not done

- **No support for Cargo, Go modules, pip or Composer.** The lockfile readers are npm, pnpm and
  yarn only.
- **`--registry` fetches one packument per added package with no caching**, which is slow on a
  change that adds hundreds. It is off by default.
- **The age rule needs the registry**, so it reports unknown offline. There is no local source
  for a first-publish date.
- **Maintainer changes are not tracked.** A package whose publishing account changed hands last
  week is the same shape of risk as a brand-new name, and the gate does not look at that.
- **pnpm workspace and yarn Berry lockfiles are untested.** Only pnpm v9 and yarn v1 were
  measured against real files.

## Status

```
$ bash scripts/verify.sh

0. environment
        node v24.13.0
        Python 3.12.3
  ok    node and python present

1. unit suite, positives paired with negative controls
  ok    0 unit tests passed
  ok    12 negative controls in the suite, so a flag-everything gate would fail it

2. the exit code, which is the product
  ok    exit 0 on a clean tree and exit 1 on a real violation
        BLOCK   esbuild@0.25.0  [install-script]
        BLOCK   gpl-thing@2.0.0  [license-class]
        REVIEW  lgpl-thing@1.0.0  [license-class]
        clean: 0 blocking, 0 to review, 0 noted
  ok    a permissive dual license containing the string MPL did not trip the gate
  ok    an unchanged lockfile adds nothing and exits 0

3. a run that could not complete must not look like a clean one
  ok    missing lockfile, bad flag and unparseable config all exit 2, not 0
        install-gate: lockfile not found: nope.json

4. an independent re-derivation, sharing no code
        agrees on 5 added packages, 1 install-script blocks, 1 license blocks, exit 1
  ok    the independent checker agrees on the fixture
          license blocks differ: only-gate=['ansi-styles@6.2.1', 'left-pad@1.3.0'] only-checker=[]
  ok    and it disagrees when the gate is broken, so its agreement means something

5. the checker really is independent
        imports only ['argparse', 'json', 'os', 're', 'sys']; no subprocess, no exec, and no string constant naming a module of the gate
  ok    no shared code with the gate

6. real dependency trees and the false-positive audit
        14 trees found
  ok    14 of 14 real trees re-derived independently with no disagreement
  ok    the tree measurement reruns
        distinct findings audited: 51 (from 82 across all trees)
          true-positive          51
        false-positive rate: 0/51 = 0.0%
        correct but low value: 1
        wrote results/fp_audit.json
        51 findings judged, 0 false positives, 1 correct but low value
  ok    the audit reaches a verdict on every finding
        67 real changes replayed: median 2 findings, mean 1.37, worst 7; 7 would block
  ok    noise measured on real history and within bounds

7. the Action definition
        action.yml parses: 9 inputs all reaching the step, 6 outputs all backed by a writer, 1 composite step(s) with a shell
          inputs:  base-ref, config, fail-on, lockfile, min-age-days, node-modules, on-unknown, registry, working-directory
          outputs: added, blocking, findings, report, review, unknowns
          writers: ["added", "blocking", "findings", "report", "review", "unknowns"]
  ok    action.yml parses and matches the code
          declared but never passed to the step, so setting them does nothing: ['base-ref']
  ok    and it fails on a misspelled input, which is the typo it exists to catch

8. the page rebuilds from the committed results
        wrote docs/index.html (12804 bytes)
          5689 packages, 36 with install scripts, false-positive rate 0%
  ok    docs/index.html is exactly what the results produce
        the page carries all 3 headline numbers and all 10 install-script package names
  ok    the page contains the measured numbers

9. the README says what the results say
        README states 5 measured values, all matching results/, and 39 unit tests, matching the suite
  ok    the README's numbers are the measured ones

10. sabotage
        exit-code-always-zero: dirty fixture: exit 1 -> 0, 3 findings -> 3
        exit-code-always-zero: unit suite 1, independent checker 1
  ok    sabotage "exit-code-always-zero" is caught
        unknown-becomes-clean: unknown fixture: 4 unestablished facts -> 0, 2 findings -> 1
        unknown-becomes-clean: unit suite 1, independent checker 0
  ok    sabotage "unknown-becomes-clean" is caught
        lockfile-flag-inverted: dirty fixture: exit 1 -> 1, 3 findings -> 8
        lockfile-flag-inverted: unit suite 1, independent checker 0
  ok    sabotage "lockfile-flag-inverted" is caught
        license-by-substring: dirty fixture: exit 1 -> 1, 3 findings -> 3
        license-by-substring: unit suite 1, independent checker 1
  ok    sabotage "license-by-substring" is caught
        install-scripts-never-seen: dirty fixture: exit 1 -> 1, 3 findings -> 3
        install-scripts-never-seen: unit suite 1, independent checker 1
  ok    sabotage "install-scripts-never-seen" is caught
        nothing-is-ever-added: dirty fixture: exit 1 -> 0, 3 findings -> 0
        nothing-is-ever-added: unit suite 1, independent checker 1
  ok    sabotage "nothing-is-ever-added" is caught
        collapse-drops-findings: dirty fixture: exit 1 -> 1, 3 findings -> 2
        collapse-drops-findings: unit suite 1, independent checker 1
  ok    sabotage "collapse-drops-findings" is caught

11. hygiene
        29 tracked files, none contain NUL, so the scans below can read all of them
  ok    no tracked file is binary to the scans
  ok    no absolute home paths in tracked files
  ok    no credential-shaped strings
  ok    no node_modules is tracked
  ok    no tracked file over 800 KB
  ok    no em dashes in tracked prose

32 passed, 0 failed
VERIFY OK
```

Task DEVT-029 from the 1000-task catalog. MIT.
