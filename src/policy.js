// Turning facts into findings.
//
// The design constraint that matters most here is that a gate people turn off protects nobody.
// Two things follow from it. The gate only looks at packages a change ADDS, so a repo with a
// thousand existing dependencies does not produce a thousand findings on its first run. And an
// accepted package goes in an allowlist with a written reason, so the second pull request that
// touches it is silent.

import { classifyLicense } from "./spdx.js";

export const SEVERITIES = ["block", "review", "note"];

export const DEFAULT_CONFIG = {
  // Severity per license class. Weak copyleft is a review rather than a block because
  // depending on an MPL-2.0 or LGPL library is normal and the obligation is file level or
  // linkage level, which is a judgement a human makes with the context of the project.
  licenseClasses: {
    "public-domain": "allow",
    permissive: "allow",
    "weak-copyleft": "review",
    "strong-copyleft": "block",
    "network-copyleft": "block",
    proprietary: "block",
    nonstandard: "review",
    unknown: "review",
  },
  allowLicenses: [],
  denyLicenses: [],
  installScriptSeverity: "block",
  allowInstallScripts: [],
  minAgeDays: 14,
  newPackageSeverity: "review",
  // What to do when a fact could not be established. "review" surfaces it, "note" records it
  // without weight, "block" refuses to merge on an unverifiable dependency.
  onUnknown: "review",
  ignorePackages: [],
};

export function loadConfig(userConfig) {
  const cfg = { ...DEFAULT_CONFIG, ...(userConfig || {}) };
  cfg.licenseClasses = { ...DEFAULT_CONFIG.licenseClasses, ...(userConfig?.licenseClasses || {}) };
  cfg.allowInstallScripts = (cfg.allowInstallScripts || []).map((a) =>
    typeof a === "string" ? { name: a } : a
  );
  const bad = [];
  for (const [k, v] of Object.entries(cfg.licenseClasses)) {
    if (!["allow", "note", "review", "block"].includes(v)) bad.push(`licenseClasses.${k}=${v}`);
  }
  for (const key of ["installScriptSeverity", "newPackageSeverity", "onUnknown"]) {
    if (!["allow", "note", "review", "block"].includes(cfg[key])) bad.push(`${key}=${cfg[key]}`);
  }
  if (typeof cfg.minAgeDays !== "number" || cfg.minAgeDays < 0 || !Number.isFinite(cfg.minAgeDays)) {
    bad.push(`minAgeDays=${cfg.minAgeDays}`);
  }
  if (bad.length) {
    const err = new Error(`invalid config: ${bad.join(", ")}`);
    err.userError = true;
    throw err;
  }
  return cfg;
}

function allowEntryFor(cfg, ev) {
  for (const a of cfg.allowInstallScripts) {
    if (a.name !== ev.name) continue;
    if (Array.isArray(a.versions) && a.versions.length && !a.versions.includes(ev.version)) {
      continue;
    }
    return a;
  }
  return null;
}

function daysBetween(a, b) {
  return (b - a) / 86400000;
}

/**
 * @param {Array} evidence output of gather()
 * @param {object} cfg from loadConfig
 * @param {Date} now
 * @returns {Array} findings
 */
export function evaluate(evidence, cfg, now = new Date()) {
  const findings = [];

  for (const ev of evidence) {
    if (cfg.ignorePackages.includes(ev.name)) continue;

    // --- install scripts -------------------------------------------------------------
    if (!ev.installScript.known) {
      findings.push({
        package: ev.key,
        name: ev.name,
        version: ev.version,
        rule: "install-script-unknown",
        severity: cfg.onUnknown,
        summary: "cannot tell whether this package runs an install script",
        detail: ev.installScript.source,
        evidence: { source: ev.installScript.source },
      });
    } else if (ev.installScript.value) {
      const allowed = allowEntryFor(cfg, ev);
      const names = ev.scriptNames.length ? ev.scriptNames.join(", ") : "install lifecycle";
      if (allowed) {
        findings.push({
          package: ev.key,
          name: ev.name,
          version: ev.version,
          rule: "install-script-allowed",
          severity: "note",
          summary: `runs ${names}, previously accepted`,
          detail: allowed.reason
            ? `allowlisted: ${allowed.reason}`
            : "allowlisted with no reason recorded, which is worth fixing",
          evidence: { source: ev.installScript.source, scripts: ev.scriptBodies || null },
        });
      } else {
        findings.push({
          package: ev.key,
          name: ev.name,
          version: ev.version,
          rule: "install-script",
          severity: cfg.installScriptSeverity,
          summary: `runs ${names} at install time`,
          detail:
            "This executes on every developer machine and in every CI job that installs " +
            "dependencies, with whatever privileges the install has.",
          evidence: { source: ev.installScript.source, scripts: ev.scriptBodies || null },
        });
      }
    }

    // --- licenses --------------------------------------------------------------------
    const lic = classifyLicense(ev.license.known ? ev.license.value : null);
    if (!ev.license.known) {
      findings.push({
        package: ev.key,
        name: ev.name,
        version: ev.version,
        rule: "license-unknown",
        severity: cfg.onUnknown,
        summary: "no license recorded by any source consulted",
        detail: ev.license.source,
        evidence: { source: ev.license.source },
      });
    } else {
      const expr = lic.expression;
      const explicitlyDenied = cfg.denyLicenses.includes(expr);
      const explicitlyAllowed = cfg.allowLicenses.includes(expr);
      let sev = cfg.licenseClasses[lic.class] ?? "review";
      if (explicitlyAllowed) sev = "allow";
      if (explicitlyDenied) sev = "block";
      if (sev !== "allow") {
        findings.push({
          package: ev.key,
          name: ev.name,
          version: ev.version,
          rule: lic.parsed ? "license-class" : "license-unparsed",
          severity: sev,
          summary: `license ${JSON.stringify(expr)} classified ${lic.class}`,
          detail: lic.parsed
            ? `SPDX identifiers seen: ${lic.ids.join(", ")}`
            : "this string is not an SPDX expression, so it was not classified by identifier",
          evidence: { source: ev.license.source, expression: expr, class: lic.class, ids: lic.ids },
        });
      }
    }

    // --- package age -----------------------------------------------------------------
    if (cfg.minAgeDays > 0) {
      if (!ev.published.known) {
        findings.push({
          package: ev.key,
          name: ev.name,
          version: ev.version,
          rule: "age-unknown",
          severity: cfg.onUnknown,
          summary: `cannot tell whether this package is newer than ${cfg.minAgeDays} days`,
          detail: ev.published.source,
          evidence: { source: ev.published.source },
        });
      } else {
        const created = new Date(ev.published.value);
        const age = daysBetween(created, now);
        if (Number.isNaN(age)) {
          findings.push({
            package: ev.key,
            name: ev.name,
            version: ev.version,
            rule: "age-unknown",
            severity: cfg.onUnknown,
            summary: "first-publish date could not be parsed",
            detail: String(ev.published.value),
            evidence: { source: ev.published.source },
          });
        } else if (age < cfg.minAgeDays) {
          findings.push({
            package: ev.key,
            name: ev.name,
            version: ev.version,
            rule: "new-package",
            severity: cfg.newPackageSeverity,
            summary: `first published ${age.toFixed(1)} days ago`,
            detail:
              "A name that has existed for days rather than years is the shape of a " +
              "typosquat and of a package published to sit under a dependency confusion.",
            evidence: { source: ev.published.source, created: ev.published.value, ageDays: age },
          });
        }
      }
    }

    // --- disagreement between sources -------------------------------------------------
    for (const d of ev.disagreements) {
      findings.push({
        package: ev.key,
        name: ev.name,
        version: ev.version,
        rule: "source-disagreement",
        severity: "review",
        summary: `sources disagree about ${d.field}`,
        detail: `${d.a}; ${d.b}`,
        evidence: d,
      });
    }
  }

  return findings;
}

const UNKNOWN_RULES = new Set(["install-script-unknown", "license-unknown", "age-unknown"]);

const GROUP_PHRASE = {
  "install-script-unknown": "could not be checked for install scripts",
  "license-unknown": "have no license from any source consulted",
  "age-unknown": "could not be checked for a first-publish date",
};

/**
 * Collapse repeated "I could not check this" findings into one finding per reason.
 *
 * This was added after measuring. Replaying 67 real lockfile changes produced a mean of 73
 * findings each and a worst case of 1392, and 4836 of the 4899 findings were unknowns. They
 * were also not 4836 separate facts. A pnpm lockfile records no install-script flag for ANY
 * package, so a pnpm change adding 881 packages produced 881 copies of one sentence about the
 * file format. A reviewer scrolling past that learns nothing and switches the check off.
 *
 * The information is kept rather than suppressed. One finding per reason, carrying the count
 * and a sample, says the same thing in a form someone will read, and the per-package facts stay
 * in the JSON output for anything that wants them.
 */
export function collapseUnknowns(findings, sampleSize = 5) {
  const groups = new Map();
  const out = [];
  for (const f of findings) {
    const gk = groupKey(f);
    if (gk === null) {
      out.push(f);
      continue;
    }
    if (!groups.has(gk)) groups.set(gk, []);
    groups.get(gk).push(f);
  }
  for (const [, group] of groups) {
    if (group.length === 1) {
      out.push(group[0]);
      continue;
    }
    const first = group[0];
    const sample = group.slice(0, sampleSize).map((f) => f.package);
    const isLicense = first.rule === "license-class" || first.rule === "license-unparsed";
    out.push({
      package: `${group.length} packages`,
      name: null,
      version: null,
      rule: first.rule,
      severity: first.severity,
      count: group.length,
      packages: group.map((f) => f.package),
      summary: isLicense
        ? `${group.length} packages under ${JSON.stringify(first.evidence?.expression ?? "")}, ` +
          `classified ${first.evidence?.class}`
        : `${group.length} packages ${GROUP_PHRASE[first.rule] ?? "could not be checked"}`,
      detail: first.detail,
      evidence: { ...first.evidence, sample },
    });
  }
  return out;
}

/**
 * Which findings are one decision rather than many.
 *
 * Unknowns group by their reason. "This lockfile format records no license" is a fact about the
 * file format, not 881 separate facts about 881 packages.
 *
 * License findings group by the exact license string. Accepting MPL-2.0 is a call a team makes
 * once. Measured on real trees this is the difference between 64 findings and 3: lightningcss
 * ships one prebuilt binary per platform, each its own package, so a single MPL-2.0 dependency
 * arrived as sixty near-identical lines.
 *
 * Install-script findings deliberately do NOT group. Each is a distinct piece of code that will
 * execute, and the measured count across fourteen real dependency trees was 24. Reading
 * twenty-four lines is the job the gate exists to create.
 *
 * The key uses a NUL separator because it cannot occur in a rule name or a license string.
 * It is written as the escape \0 rather than embedded as a byte, because a source file
 * containing a real NUL is classified as binary by git and by grep, and the secret scan in
 * scripts/verify.sh then skips the whole file. That happened to this exact line.
 */
function groupKey(f) {
  const SEP = "\0";
  if (UNKNOWN_RULES.has(f.rule)) return `${f.rule}${SEP}${f.detail}`;
  if (f.rule === "license-class" || f.rule === "license-unparsed") {
    return [f.rule, f.evidence?.expression, f.evidence?.class, f.severity].join(SEP);
  }
  return null;
}

export function severityCounts(findings) {
  const c = { block: 0, review: 0, note: 0 };
  for (const f of findings) if (c[f.severity] !== undefined) c[f.severity] += 1;
  return c;
}

/** Exit code contract: 0 clean, 1 blocking findings, 2 could not run. */
export function exitCodeFor(findings, failOn) {
  const order = { note: 0, review: 1, block: 2 };
  const threshold = order[failOn];
  if (threshold === undefined) {
    const err = new Error(`--fail-on must be one of note, review, block (got ${failOn})`);
    err.userError = true;
    throw err;
  }
  return findings.some((f) => (order[f.severity] ?? -1) >= threshold) ? 1 : 0;
}
