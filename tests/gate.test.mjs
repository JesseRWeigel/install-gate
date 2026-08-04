// Every test that proves the gate fires is paired with one that proves it stays quiet.
//
// A gate with no negative control is indistinguishable from a gate that flags everything, and a
// gate that flags everything gets switched off within a week. So the safe inputs here carry as
// much weight as the unsafe ones, and several of them exist specifically because a plausible
// implementation would have tripped on them: a permissive dual license containing the string
// MPL, an unchanged lockfile, an already-present risky package, and an allowlisted one.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { parseLockfile, parsePnpmKey, nameFromNpmPath } from "../src/lockfile.js";
import { classifyLicense } from "../src/spdx.js";
import { gather, indexNodeModules, normaliseLicenseField } from "../src/evidence.js";
import { loadConfig, evaluate, exitCodeFor, collapseUnknowns } from "../src/policy.js";
import { renderText, renderMarkdown, acceptanceLine } from "../src/report.js";
import { parseArgs } from "../src/cli.js";
import { npmLock, pnpmLock, yarnLock, buildTree, rm } from "./fixtures.mjs";

const execFileP = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, "..", "bin", "install-gate.mjs");

const SAFE = ["left-pad@1.3.0", "ansi-styles@6.2.1"];
const RISKY = ["left-pad@1.3.0", "esbuild@0.25.0", "gpl-thing@2.0.0"];

async function runGate(args) {
  try {
    const { stdout, stderr } = await execFileP("node", [BIN, ...args]);
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

// ---------------------------------------------------------------- SPDX

test("spdx: permissive identifiers are permissive", () => {
  for (const id of ["MIT", "ISC", "Apache-2.0", "BSD-3-Clause", "Python-2.0"]) {
    assert.equal(classifyLicense(id).class, "permissive", id);
  }
});

test("spdx: copyleft is separated by strength rather than by the substring GPL", () => {
  assert.equal(classifyLicense("GPL-3.0-only").class, "strong-copyleft");
  assert.equal(classifyLicense("AGPL-3.0-or-later").class, "network-copyleft");
  // NEGATIVE CONTROL: LGPL contains "GPL" and is a different obligation. A substring check
  // would call this strong copyleft and block a dependency nobody needed to block.
  assert.equal(classifyLicense("LGPL-3.0-or-later").class, "weak-copyleft");
  assert.equal(classifyLicense("MPL-2.0").class, "weak-copyleft");
});

test("spdx: OR takes the most permissive branch and AND takes the most restrictive", () => {
  // NEGATIVE CONTROL: this string contains MPL, and it is permissive, because you may choose
  // the Apache option. dompurify ships exactly this expression.
  assert.equal(classifyLicense("(MPL-2.0 OR Apache-2.0)").class, "permissive");
  assert.equal(classifyLicense("(MIT OR CC0-1.0)").class, "public-domain");
  // @img/sharp-win32-x64 ships exactly this one, and every obligation applies.
  assert.equal(classifyLicense("Apache-2.0 AND LGPL-3.0-or-later").class, "weak-copyleft");
  assert.equal(classifyLicense("MIT AND ISC").class, "permissive");
});

test("spdx: lowercase or is accepted because real packages publish it", () => {
  const r = classifyLicense("(MIT or Apache-2.0)");
  assert.equal(r.parsed, true);
  assert.equal(r.class, "permissive");
});

test("spdx: a WITH exception classifies on its base identifier", () => {
  assert.equal(classifyLicense("GPL-2.0-only WITH Classpath-exception-2.0").class, "strong-copyleft");
});

test("spdx: strings that are not SPDX say so instead of being guessed at", () => {
  // Not an expression at all. The first version of the parser read only the leading token of
  // "SIL OPEN FONT LICENSE" and reported the identifier "SIL", which is a confident wrong
  // answer rather than an admission.
  for (const s of ["SIL OPEN FONT LICENSE", "SEE LICENSE IN LICENSE.txt", "The MIT Licence"]) {
    const r = classifyLicense(s);
    assert.equal(r.parsed, false, s);
    assert.equal(r.class, "nonstandard", s);
  }
  // Syntactically a valid single identifier, but not one SPDX defines. That is a different
  // thing from unparseable and it is reported differently.
  const bsd = classifyLicense("BSD");
  assert.equal(bsd.parsed, true);
  assert.equal(bsd.class, "nonstandard");
  const none = classifyLicense(null);
  assert.equal(none.class, "unknown");
  assert.equal(none.parsed, false);
});

test("spdx: an unbalanced expression is nonstandard rather than a thrown error", () => {
  const r = classifyLicense("(MIT OR");
  assert.equal(r.parsed, false);
});

// ---------------------------------------------------------------- lockfiles

test("npm lockfile v3 carries install-script and license facts", () => {
  const parsed = parseLockfile(npmLock(RISKY), "/x/package-lock.json");
  assert.equal(parsed.kind, "npm");
  assert.equal(parsed.packages.size, 3);
  assert.equal(parsed.packages.get("esbuild@0.25.0").hasInstallScript, true);
  // NEGATIVE CONTROL: a package with no scripts must read false, not unknown. npm omits the
  // key when false, and treating an omission as unknown would make every clean tree noisy.
  assert.equal(parsed.packages.get("left-pad@1.3.0").hasInstallScript, false);
  assert.equal(parsed.packages.get("left-pad@1.3.0").license, "MIT");
});

test("npm lockfile v1 reports unknown rather than false", () => {
  const v1 = JSON.stringify({
    name: "old", lockfileVersion: 1,
    dependencies: { "left-pad": { version: "1.3.0", resolved: "x", integrity: "y" } },
  });
  const parsed = parseLockfile(v1, "/x/package-lock.json");
  const e = parsed.packages.get("left-pad@1.3.0");
  assert.equal(e.hasInstallScript, null);
  assert.equal(e.license, null);
  assert.match(e.installScriptSource, /lockfileVersion 1/);
});

test("pnpm and yarn lockfiles yield identity only, and say so", () => {
  const p = parseLockfile(pnpmLock(RISKY), "/x/pnpm-lock.yaml");
  assert.equal(p.kind, "pnpm");
  assert.equal(p.packages.size, 3);
  assert.equal(p.packages.get("esbuild@0.25.0").hasInstallScript, null);
  const y = parseLockfile(yarnLock(RISKY), "/x/yarn.lock");
  assert.equal(y.packages.size, 3);
  assert.equal(y.packages.get("gpl-thing@2.0.0").hasInstallScript, null);
});

test("pnpm keys with peer suffixes and scopes parse", () => {
  assert.deepEqual(parsePnpmKey("@ai-sdk/openai@3.0.48(zod@4.3.6)"), {
    name: "@ai-sdk/openai", version: "3.0.48",
  });
  assert.deepEqual(parsePnpmKey("left-pad@1.3.0"), { name: "left-pad", version: "1.3.0" });
  assert.deepEqual(parsePnpmKey("/left-pad/1.3.0"), { name: "left-pad", version: "1.3.0" });
  assert.equal(parsePnpmKey("not-a-key"), null);
});

test("a nested npm path resolves to the package name", () => {
  assert.equal(nameFromNpmPath("node_modules/a/node_modules/@s/b"), "@s/b");
  assert.equal(nameFromNpmPath("node_modules/left-pad"), "left-pad");
});

test("an unreadable lockfile raises rather than returning empty", () => {
  assert.throws(() => parseLockfile("{not json", "/x/package-lock.json"), /not valid JSON/);
  assert.throws(() => parseLockfile("", "/x/Cargo.lock"), /unrecognised lockfile name/);
});

// ---------------------------------------------------------------- the installed tree

test("the node_modules index finds packages in flat, nested and pnpm layouts", () => {
  for (const layout of ["flat", "nested", "pnpm"]) {
    const dir = buildTree({ layout, installed: RISKY });
    try {
      const idx = indexNodeModules(dir);
      assert.ok(idx.index.has("esbuild@0.25.0"), `${layout} did not find esbuild`);
      assert.ok(idx.index.has("gpl-thing@2.0.0"), `${layout} did not find gpl-thing`);
    } finally {
      rm(dir);
    }
  }
});

test("the tarball overrides the lockfile and the disagreement is recorded", () => {
  // The lockfile claims left-pad has an install script and that esbuild does not. Both are
  // wrong, and both must be caught, because a lockfile is metadata about a tarball rather than
  // the tarball.
  const dir = buildTree({ layout: "flat", installed: RISKY });
  try {
    const parsed = parseLockfile(
      npmLock(RISKY, { lie: { "left-pad": true, esbuild: false } }),
      "/x/package-lock.json"
    );
    const idx = indexNodeModules(dir);
    const lp = gather(parsed.packages.get("left-pad@1.3.0"), {
      root: dir, useNodeModules: true, installedIndex: idx,
    });
    assert.equal(lp.installScript.value, false);
    assert.equal(lp.disagreements.length, 1);
    const eb = gather(parsed.packages.get("esbuild@0.25.0"), {
      root: dir, useNodeModules: true, installedIndex: idx,
    });
    assert.equal(eb.installScript.value, true);
    assert.deepEqual(eb.scriptNames, ["postinstall"]);
    assert.equal(eb.disagreements.length, 1);
  } finally {
    rm(dir);
  }
});

test("a package missing from node_modules stays unknown rather than becoming clean", () => {
  const dir = buildTree({ layout: "flat", installed: ["left-pad@1.3.0"] });
  try {
    const parsed = parseLockfile(pnpmLock(RISKY), "/x/pnpm-lock.yaml");
    const ev = gather(parsed.packages.get("esbuild@0.25.0"), {
      root: dir, useNodeModules: true, installedIndex: indexNodeModules(dir),
    });
    assert.equal(ev.installScript.known, false);
    assert.match(ev.notes.join(" "), /not present in node_modules/);
  } finally {
    rm(dir);
  }
});

test("legacy license shapes normalise", () => {
  assert.equal(normaliseLicenseField({ license: "MIT" }), "MIT");
  assert.equal(normaliseLicenseField({ license: { type: "MIT" } }), "MIT");
  assert.equal(normaliseLicenseField({ licenses: [{ type: "MIT" }, { type: "Apache-2.0" }] }),
    "(MIT OR Apache-2.0)");
  assert.equal(normaliseLicenseField({}), null);
});

// ---------------------------------------------------------------- policy

function evaluateKeys(keys, cfg = {}, opts = {}) {
  const parsed = parseLockfile(npmLock(keys), "/x/package-lock.json");
  const evidence = [...parsed.packages.values()].map((e) => gather(e, opts));
  return collapseUnknowns(evaluate(evidence, loadConfig(cfg), opts.now));
}

test("an install script blocks, and a clean tree does not", () => {
  const risky = evaluateKeys(RISKY, { minAgeDays: 0 });
  assert.equal(risky.filter((f) => f.rule === "install-script").length, 1);
  assert.equal(exitCodeFor(risky, "block"), 1);
  // NEGATIVE CONTROL, and the one that matters most: two ordinary MIT packages with no scripts
  // must produce nothing at all and exit 0.
  const safe = evaluateKeys(SAFE, { minAgeDays: 0 });
  assert.deepEqual(safe, []);
  assert.equal(exitCodeFor(safe, "block"), 0);
});

test("an allowlisted install script stops blocking but is still reported", () => {
  const cfg = {
    minAgeDays: 0,
    allowInstallScripts: [{ name: "esbuild", versions: ["0.25.0"], reason: "builds a binary" }],
  };
  const f = evaluateKeys(RISKY, cfg);
  const allowed = f.find((x) => x.rule === "install-script-allowed");
  assert.ok(allowed, "the allowlisted package vanished entirely, which hides it");
  assert.equal(allowed.severity, "note");
  assert.equal(f.filter((x) => x.rule === "install-script").length, 0);
  // NEGATIVE CONTROL for the allowlist: a version that is not on it still blocks.
  const other = evaluateKeys(["esbuild@0.25.0"], {
    minAgeDays: 0,
    allowInstallScripts: [{ name: "esbuild", versions: ["0.24.0"], reason: "old" }],
  });
  assert.equal(other.filter((x) => x.rule === "install-script").length, 1);
});

test("license severity follows the class, and permissive produces no finding", () => {
  const f = evaluateKeys(
    ["gpl-thing@2.0.0", "agpl-thing@1.0.0", "axe-core@4.11.1", "left-pad@1.3.0",
     "dual-thing@1.0.0", "lowercase-or@1.0.0"],
    { minAgeDays: 0 }
  );
  const byPkg = Object.fromEntries(
    f.filter((x) => x.rule.startsWith("license-")).map((x) => [x.package, x.severity])
  );
  assert.equal(byPkg["gpl-thing@2.0.0"], "block");
  assert.equal(byPkg["agpl-thing@1.0.0"], "block");
  assert.equal(byPkg["axe-core@4.11.1"], "review");
  // NEGATIVE CONTROLS: none of these may appear at all.
  assert.equal(byPkg["left-pad@1.3.0"], undefined);
  assert.equal(byPkg["dual-thing@1.0.0"], undefined);
  assert.equal(byPkg["lowercase-or@1.0.0"], undefined);
});

test("a license that cannot be parsed is surfaced, not assumed either way", () => {
  const f = evaluateKeys(["fonty@1.7.0"], { minAgeDays: 0 });
  const lic = f.find((x) => x.rule === "license-unparsed");
  assert.ok(lic, `expected license-unparsed, got ${f.map((x) => x.rule)}`);
  assert.ok(lic);
  assert.equal(lic.severity, "review");
  assert.notEqual(lic.severity, "allow");
});

test("allowLicenses and denyLicenses override the class", () => {
  const allowed = evaluateKeys(["gpl-thing@2.0.0"], {
    minAgeDays: 0, allowLicenses: ["GPL-3.0-only"],
  });
  assert.equal(allowed.filter((x) => x.rule.startsWith("license-")).length, 0);
  const denied = evaluateKeys(["left-pad@1.3.0"], { minAgeDays: 0, denyLicenses: ["MIT"] });
  assert.equal(denied.find((x) => x.rule === "license-class").severity, "block");
});

test("an unknown fact is a finding whose severity is configurable, and never silently clean", () => {
  const parsed = parseLockfile(pnpmLock(SAFE), "/x/pnpm-lock.yaml");
  const ev = [...parsed.packages.values()].map((e) => gather(e, {}));
  const review = collapseUnknowns(evaluate(ev, loadConfig({ minAgeDays: 0 })));
  assert.ok(review.some((f) => f.rule === "install-script-unknown"));
  assert.equal(exitCodeFor(review, "block"), 0);
  const blocking = collapseUnknowns(
    evaluate(ev, loadConfig({ minAgeDays: 0, onUnknown: "block" }))
  );
  assert.equal(exitCodeFor(blocking, "block"), 1);
});

test("the age rule fires on a new package and stays quiet on an old one", () => {
  const now = new Date("2026-08-03T00:00:00Z");
  const packument = (created) => ({ time: { created }, versions: { "1.3.0": {} } });
  const parsed = parseLockfile(npmLock(["left-pad@1.3.0"]), "/x/package-lock.json");
  const e = parsed.packages.get("left-pad@1.3.0");

  const fresh = evaluate([gather(e, { packument: packument("2026-08-01T00:00:00Z") })],
    loadConfig({ minAgeDays: 14 }), now);
  const hit = fresh.find((f) => f.rule === "new-package");
  assert.ok(hit);
  assert.equal(hit.severity, "review");

  // NEGATIVE CONTROL: a package first published years ago must not be flagged.
  const old = evaluate([gather(e, { packument: packument("2014-01-01T00:00:00Z") })],
    loadConfig({ minAgeDays: 14 }), now);
  assert.equal(old.filter((f) => f.rule === "new-package").length, 0);
  assert.equal(old.filter((f) => f.rule === "age-unknown").length, 0);
});

test("collapsing groups unknowns and licenses but never install scripts", () => {
  const many = ["esbuild@0.25.0", "sharp@0.34.5", "node-sass@9.0.0", "creepy@0.0.1"];
  const f = evaluateKeys(many, { minAgeDays: 0 });
  assert.equal(f.filter((x) => x.rule === "install-script").length, 4,
    "install-script findings must stay one per package");

  const licenses = evaluateKeys(["axe-core@4.11.1", "and-thing@1.0.0"], { minAgeDays: 0 });
  // Different expressions, so they do not merge.
  assert.equal(licenses.filter((x) => x.rule === "license-class").length, 2);

  const parsed = parseLockfile(pnpmLock(["left-pad@1.3.0", "ansi-styles@6.2.1", "esbuild@0.25.0"]),
    "/x/pnpm-lock.yaml");
  const ev = [...parsed.packages.values()].map((e) => gather(e, {}));
  const grouped = collapseUnknowns(evaluate(ev, loadConfig({ minAgeDays: 0 })));
  const g = grouped.find((x) => x.rule === "install-script-unknown");
  assert.equal(g.count, 3);
  assert.equal(g.packages.length, 3);
  assert.equal(grouped.filter((x) => x.rule === "install-script-unknown").length, 1);
});

test("an invalid config is rejected rather than partly applied", () => {
  assert.throws(() => loadConfig({ onUnknown: "maybe" }), /invalid config/);
  assert.throws(() => loadConfig({ minAgeDays: -1 }), /invalid config/);
  assert.throws(() => loadConfig({ licenseClasses: { permissive: "nope" } }), /invalid config/);
});

test("exitCodeFor honours the threshold and rejects a bad one", () => {
  const f = [{ severity: "review" }];
  assert.equal(exitCodeFor(f, "block"), 0);
  assert.equal(exitCodeFor(f, "review"), 1);
  assert.equal(exitCodeFor([], "note"), 0);
  assert.throws(() => exitCodeFor(f, "loud"), /--fail-on/);
});

// ---------------------------------------------------------------- report

test("every actionable finding carries the line that accepts it", () => {
  const dir = buildTree({ layout: "flat", installed: RISKY });
  const parsed = parseLockfile(npmLock(RISKY), "/x/package-lock.json");
  const idx = indexNodeModules(dir);
  const f = collapseUnknowns(evaluate(
    [...parsed.packages.values()].map((e) =>
      gather(e, { root: dir, useNodeModules: true, installedIndex: idx })),
    loadConfig({ minAgeDays: 0 })
  ));
  rm(dir);
  for (const finding of f) {
    if (["install-script", "license-class", "new-package"].includes(finding.rule)) {
      assert.ok(acceptanceLine(finding, {}), `${finding.rule} has no acceptance line`);
    }
  }
  const text = renderText({ findings: f, added: RISKY, config: {}, sources: ["x"], unknowns: 0 });
  assert.match(text, /esbuild@0\.25\.0/);
  assert.match(text, /node install\.js/);
  assert.match(text, /allowInstallScripts/);
  const md = renderMarkdown({ findings: f, added: RISKY, counts: { block: 2, review: 0, note: 0 } });
  assert.match(md, /\| block \|/);
});

test("a clean run renders as clean", () => {
  const text = renderText({ findings: [], added: [], config: {}, sources: ["x"], unknowns: 0 });
  assert.match(text, /no findings/);
});

// ---------------------------------------------------------------- argv

test("argv parsing rejects what it cannot honour", () => {
  assert.throws(() => parseArgs(["--nope"]), /unknown argument/);
  assert.throws(() => parseArgs(["--lockfile"]), /needs a value/);
  assert.throws(() => parseArgs(["--format", "xml"]), /--format/);
  assert.throws(() => parseArgs(["--min-age-days", "soon"]), /must be a number/);
  const ok = parseArgs(["--lockfile", "a.json", "--node-modules", "--fail-on", "review"]);
  assert.equal(ok.lockfile, "a.json");
  assert.equal(ok.nodeModules, true);
});

// ---------------------------------------------------------------- end to end exit codes

test("end to end: exit 1 on a real violation, exit 0 on a clean tree", async () => {
  const risky = buildTree({
    layout: "flat", installed: RISKY,
    lockfile: { name: "package-lock.json", text: npmLock(RISKY) },
  });
  const clean = buildTree({
    layout: "flat", installed: SAFE,
    lockfile: { name: "package-lock.json", text: npmLock(SAFE) },
  });
  try {
    const bad = await runGate(["--cwd", risky, "--node-modules", "--min-age-days", "0"]);
    assert.equal(bad.code, 1, bad.stdout + bad.stderr);
    assert.match(bad.stdout, /BLOCK/);
    const good = await runGate(["--cwd", clean, "--node-modules", "--min-age-days", "0"]);
    assert.equal(good.code, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /no findings/);
  } finally {
    rm(risky);
    rm(clean);
  }
});

test("end to end: only what a change ADDS is judged", async () => {
  const dir = buildTree({
    layout: "flat", installed: RISKY,
    lockfile: { name: "package-lock.json", text: npmLock(RISKY) },
  });
  try {
    // The risky packages were already there, so the change adds nothing and must pass.
    fs.writeFileSync(path.join(dir, "base.json"), npmLock(RISKY));
    const same = await runGate([
      "--cwd", dir, "--base", "base.json", "--node-modules", "--min-age-days", "0",
    ]);
    assert.equal(same.code, 0, same.stdout);
    assert.match(same.stdout, /0 package\(s\) added/);

    // NEGATIVE CONTROL for the diff itself: with a base that lacks esbuild, it must fire.
    fs.writeFileSync(path.join(dir, "base2.json"), npmLock(["left-pad@1.3.0"]));
    const added = await runGate([
      "--cwd", dir, "--base", "base2.json", "--node-modules", "--min-age-days", "0",
    ]);
    assert.equal(added.code, 1, added.stdout);
    assert.match(added.stdout, /esbuild@0\.25\.0/);
  } finally {
    rm(dir);
  }
});

test("end to end: a version bump of an existing package counts as added", async () => {
  const dir = buildTree({
    layout: "flat", installed: ["esbuild@0.25.0"],
    lockfile: { name: "package-lock.json", text: npmLock(["esbuild@0.25.0"]) },
  });
  try {
    // A different version is a different tarball, so it must be judged again. This is the case
    // that matters most: a package can add an install script in a patch release.
    fs.writeFileSync(path.join(dir, "base.json"), npmLock(["node-sass@9.0.0"]));
    const r = await runGate(["--cwd", dir, "--base", "base.json", "--min-age-days", "0"]);
    assert.equal(r.code, 1);
    assert.match(r.stdout, /1 package\(s\) added/);
  } finally {
    rm(dir);
  }
});

test("end to end: exit 2 when the gate cannot run", async () => {
  const dir = buildTree({ layout: "flat", installed: [] });
  try {
    const missing = await runGate(["--cwd", dir, "--lockfile", "nope.json"]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /lockfile not found/);

    fs.writeFileSync(path.join(dir, "package-lock.json"), npmLock(SAFE));
    const nm = await runGate(["--cwd", dir, "--node-modules"]);
    assert.equal(nm.code, 2);
    assert.match(nm.stderr, /no node_modules directory/);

    fs.writeFileSync(path.join(dir, "bad.json"), "{oops");
    const cfg = await runGate(["--cwd", dir, "--config", "bad.json"]);
    assert.equal(cfg.code, 2);
    assert.match(cfg.stderr, /not valid JSON/);

    const flag = await runGate(["--cwd", dir, "--wat"]);
    assert.equal(flag.code, 2);

    // NEGATIVE CONTROL for exit 2: the same directory, run correctly, must exit 0. Without
    // this a gate that always exits 2 would pass every test above.
    const fine = await runGate(["--cwd", dir, "--min-age-days", "0"]);
    assert.equal(fine.code, 0, fine.stdout + fine.stderr);
  } finally {
    rm(dir);
  }
});

test("end to end: a config file is found and honoured", async () => {
  const dir = buildTree({
    layout: "flat", installed: RISKY,
    lockfile: { name: "package-lock.json", text: npmLock(RISKY) },
    config: {
      minAgeDays: 0,
      allowInstallScripts: [{ name: "esbuild", reason: "builds its platform binary" }],
      licenseClasses: { "strong-copyleft": "review" },
    },
  });
  try {
    const r = await runGate(["--cwd", dir, "--node-modules"]);
    assert.equal(r.code, 0, r.stdout);
    assert.match(r.stdout, /previously accepted/);
    // NEGATIVE CONTROL: the same tree without the config must block.
    fs.rmSync(path.join(dir, ".install-gate.json"));
    const r2 = await runGate(["--cwd", dir, "--node-modules", "--min-age-days", "0"]);
    assert.equal(r2.code, 1);
  } finally {
    rm(dir);
  }
});

test("end to end: json output carries per-package facts and the exit code", async () => {
  const dir = buildTree({
    layout: "flat", installed: RISKY,
    lockfile: { name: "package-lock.json", text: npmLock(RISKY) },
  });
  try {
    const r = await runGate([
      "--cwd", dir, "--node-modules", "--min-age-days", "0", "--format", "json",
    ]);
    const doc = JSON.parse(r.stdout);
    assert.equal(doc.exitCode, 1);
    assert.equal(doc.total, 3);
    const eb = doc.addedDetail.find((d) => d.package === "esbuild@0.25.0");
    assert.equal(eb.installScript.known, true);
    assert.equal(eb.installScript.value, true);
    assert.deepEqual(eb.scriptNames, ["postinstall"]);
  } finally {
    rm(dir);
  }
});

test("end to end: --base against a git ref", async () => {
  const dir = buildTree({
    layout: "flat", installed: SAFE,
    lockfile: { name: "package-lock.json", text: npmLock(SAFE) },
  });
  try {
    const g = (...a) => execFileP("git", ["-C", dir, ...a]);
    await g("init", "-q");
    await g("config", "user.email", "t@example.com");
    await g("config", "user.name", "t");
    await g("add", "package-lock.json");
    await g("commit", "-qm", "base");
    fs.writeFileSync(path.join(dir, "package-lock.json"), npmLock(RISKY));

    const r = await runGate(["--cwd", dir, "--base", "HEAD", "--min-age-days", "0"]);
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /git show HEAD/);
    assert.match(r.stdout, /2 package\(s\) added/);

    // NEGATIVE CONTROL: a ref that does not exist must exit 2, not silently pass.
    const bad = await runGate(["--cwd", dir, "--base", "no-such-ref"]);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /could not read base/);
  } finally {
    rm(dir);
  }
});

test("end to end: the registry path is exercised against a local server", async () => {
  // Served from a canned packument rather than the network, so this runs offline and still
  // covers the code that reads first-publish dates.
  const packuments = {
    "brand-new": {
      name: "brand-new",
      time: { created: new Date(Date.now() - 2 * 86400000).toISOString() },
      versions: {
        "1.0.0": {
          _id: "brand-new@1.0.0", license: "MIT", scripts: { postinstall: "node evil.js" },
        },
      },
    },
    // Shaped like a real full packument: _id present, scripts present but with no install
    // lifecycle in them. left-pad@1.3.0 really does look like this on registry.npmjs.org.
    "left-pad": {
      name: "left-pad",
      time: { created: "2014-03-20T00:00:00.000Z" },
      versions: {
        "1.3.0": {
          _id: "left-pad@1.3.0", license: "MIT",
          scripts: { test: "node test", bench: "node perf/perf.js" },
        },
      },
    },
  };
  const server = http.createServer((req, res) => {
    const name = decodeURIComponent(req.url.slice(1));
    const doc = packuments[name];
    if (!doc) {
      res.writeHead(404).end("{}");
      return;
    }
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(doc));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;

  const lock = JSON.stringify({
    name: "f", lockfileVersion: 1,
    dependencies: { "brand-new": { version: "1.0.0" }, "left-pad": { version: "1.3.0" } },
  });
  const dir = buildTree({ layout: "flat", installed: [],
    lockfile: { name: "package-lock.json", text: lock } });
  try {
    const r = await runGate([
      "--cwd", dir, "--registry", url, "--min-age-days", "14", "--format", "json",
    ]);
    const doc = JSON.parse(r.stdout);
    const rules = doc.findings.map((f) => f.rule);
    assert.ok(rules.includes("new-package"), `expected new-package, got ${rules}`);
    assert.ok(rules.includes("install-script"), `expected install-script, got ${rules}`);
    // NEGATIVE CONTROL: left-pad is old and clean, so it must contribute nothing.
    assert.equal(doc.findings.filter((f) => f.package === "left-pad@1.3.0").length, 0);
    assert.equal(doc.exitCode, 1);
  } finally {
    rm(dir);
    server.close();
  }
});

test("end to end: GITHUB_OUTPUT receives the values action.yml declares", async () => {
  const dir = buildTree({
    layout: "flat", installed: RISKY,
    lockfile: { name: "package-lock.json", text: npmLock(RISKY) },
  });
  const outFile = path.join(dir, "gh-output");
  fs.writeFileSync(outFile, "");
  try {
    await execFileP("node", [BIN, "--cwd", dir, "--node-modules", "--min-age-days", "0"], {
      env: { ...process.env, GITHUB_OUTPUT: outFile },
    }).catch((e) => e);
    const written = fs.readFileSync(outFile, "utf8");
    for (const key of ["findings", "blocking", "review", "added", "unknowns"]) {
      assert.match(written, new RegExp(`^${key}=\\d+$`, "m"), `${key} missing from GITHUB_OUTPUT`);
    }
  } finally {
    rm(dir);
  }
});
