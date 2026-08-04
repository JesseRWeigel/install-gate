// Gathering the facts, and keeping "I could not check" separate from "I checked and it is fine".
//
// Every fact is a Fact: { value, known, source }. Collapsing an unchecked fact into a false is
// the failure this whole module is shaped around, because the resulting report reads exactly
// like a clean one.

import fs from "node:fs";
import path from "node:path";

/** @typedef {{value: any, known: boolean, source: string}} Fact */

export function fact(value, source) {
  return { value, known: true, source };
}

export function unknownFact(reason) {
  return { value: null, known: false, source: reason };
}

const SCRIPT_KEYS = ["preinstall", "install", "postinstall"];

// Finding the installed copy of a package by guessing at its path does not survive contact with
// real trees. npm nests a second copy of a package under its dependent, yarn hoists whichever
// version it saw first and nests the rest, and pnpm puts every real directory inside
// node_modules/.pnpm and fills node_modules with symlinks to them. Measured on 14 real trees,
// path guessing left 957 of 5689 packages unresolved, and every one of those became an "unknown"
// finding that a reviewer would have had to read. So the tree is walked once and indexed by
// name@version instead.
export function indexNodeModules(root) {
  const index = new Map();
  const errors = [];
  const seen = new Set();

  const walk = (dir, depth) => {
    if (depth > 12) return;
    let names;
    try {
      names = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of names) {
      const name = ent.name;
      if (name === ".bin") continue;
      const full = path.join(dir, name);
      // A symlink farm entry points at a directory this walk reaches anyway, so following it
      // would double the work and can loop. .pnpm is walked directly instead.
      if (ent.isSymbolicLink()) continue;
      if (!ent.isDirectory()) continue;
      if (name.startsWith("@")) {
        walk(full, depth);
        continue;
      }
      if (name === ".pnpm") {
        // node_modules/.pnpm/<name>@<version>/node_modules/<name>/package.json
        let stores;
        try {
          stores = fs.readdirSync(full, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const s of stores) {
          if (!s.isDirectory()) continue;
          walk(path.join(full, s.name, "node_modules"), depth + 1);
        }
        continue;
      }
      if (name.startsWith(".")) continue;

      const pj = path.join(full, "package.json");
      let text = null;
      try {
        text = fs.readFileSync(pj, "utf8");
      } catch {
        text = null;
      }
      if (text !== null) {
        let doc = null;
        try {
          doc = JSON.parse(text);
        } catch (err) {
          // A package.json that exists and does not parse is an anomaly. Recording it as an
          // error keeps it distinct from a package that is simply absent.
          errors.push({ path: path.relative(root, pj), reason: err.message });
        }
        if (doc && typeof doc.name === "string" && typeof doc.version === "string") {
          const key = `${doc.name}@${doc.version}`;
          if (!index.has(key)) index.set(key, { doc, rel: path.relative(root, pj) });
          seen.add(key);
        }
      }
      const nested = path.join(full, "node_modules");
      if (fs.existsSync(nested)) walk(nested, depth + 1);
    }
  };

  const top = path.join(root, "node_modules");
  if (fs.existsSync(top)) walk(top, 0);
  return { index, errors, size: index.size };
}

/** Look an entry up in an index built by indexNodeModules. */
export function readInstalled(root, entry, built) {
  const idx = built ?? indexNodeModules(root);
  const hit = idx.index.get(entry.key);
  if (hit) return { ok: true, doc: hit.doc, rel: hit.rel };
  const anyVersion = [...idx.index.keys()].some((k) => k.slice(0, k.lastIndexOf("@")) === entry.name);
  return {
    ok: false,
    reason: anyVersion
      ? `${entry.name} is installed, but not at version ${entry.version}`
      : "not present in node_modules",
    rel: null,
  };
}

/**
 * Combine lockfile facts with node_modules facts and, when supplied, registry facts.
 * @param {object} entry from parseLockfile
 * @param {object} opts { root, useNodeModules, packument }
 */
export function gather(entry, opts = {}) {
  const root = opts.root ?? process.cwd();
  const out = {
    name: entry.name,
    version: entry.version,
    key: entry.key,
    dev: entry.dev,
    optional: entry.optional,
    integrity: entry.integrity,
    installScript: unknownFact("no source consulted"),
    scriptNames: [],
    license: unknownFact("no source consulted"),
    published: unknownFact("no source consulted"),
    disagreements: [],
    notes: [],
  };

  // 1. the lockfile
  if (entry.hasInstallScript === null) {
    out.installScript = unknownFact(entry.installScriptSource);
  } else {
    out.installScript = fact(entry.hasInstallScript, entry.installScriptSource);
  }
  if (entry.license !== null) {
    out.license = fact(entry.license, entry.licenseSource);
  } else {
    out.license = unknownFact(entry.licenseSource);
  }

  // 2. the installed tree, which is the published tarball rather than metadata about it
  if (opts.useNodeModules) {
    const got = readInstalled(root, entry, opts.installedIndex);
    if (got.ok) {
      const scripts = got.doc.scripts && typeof got.doc.scripts === "object" ? got.doc.scripts : {};
      const names = SCRIPT_KEYS.filter((k) => typeof scripts[k] === "string" && scripts[k].trim());
      const rel = got.rel;
      const tarballSays = names.length > 0;
      if (out.installScript.known && out.installScript.value !== tarballSays) {
        out.disagreements.push({
          field: "installScript",
          a: `${entry.installScriptSource} says ${out.installScript.value}`,
          b: `${rel} says ${tarballSays}`,
        });
      }
      // The tarball wins. It is the code that actually runs.
      out.installScript = fact(tarballSays, rel);
      out.scriptNames = names;
      if (names.length) {
        out.scriptBodies = Object.fromEntries(names.map((k) => [k, scripts[k]]));
      }

      const lic = normaliseLicenseField(got.doc);
      if (lic !== null) {
        if (out.license.known && out.license.value !== lic) {
          out.disagreements.push({
            field: "license",
            a: `${entry.licenseSource} says ${JSON.stringify(out.license.value)}`,
            b: `${rel} says ${JSON.stringify(lic)}`,
          });
        }
        out.license = fact(lic, rel);
      } else if (!out.license.known) {
        out.license = unknownFact(`${rel} declares no license field`);
      }
    } else {
      out.notes.push(`node_modules: ${got.reason}`);
    }
  }

  // 3. the registry, which is the only source for a first-publish date
  if (opts.packument) {
    const p = opts.packument;
    const v = p.versions && p.versions[entry.version];
    if (v) {
      if (!out.license.known) {
        const lic = normaliseLicenseField(v);
        if (lic !== null) out.license = fact(lic, "registry packument");
      }
      // A registry serves two different documents and they carry install-script information in
      // different places. Both shapes were fetched from registry.npmjs.org and inspected before
      // this was written, because guessing here produces a confident wrong answer.
      //
      //   full document (accept: application/json) mirrors each published package.json. The
      //     version object has _id and scripts, and has NO hasInstallScript field at all.
      //     Checked on fsevents and canvas: both declare install scripts and both return
      //     hasInstallScript undefined, so reading that field would have said "no script".
      //   abbreviated document (accept: application/vnd.npm.install-v1+json) has no scripts and
      //     carries hasInstallScript, set only when true. That is npm's own contract for it.
      //
      // Anything that is neither shape is unknown rather than assumed clean.
      if (!out.installScript.known) {
        if (typeof v.hasInstallScript === "boolean") {
          out.installScript = fact(v.hasInstallScript, "registry packument hasInstallScript");
        } else if (typeof v._id === "string") {
          const scripts = v.scripts && typeof v.scripts === "object" ? v.scripts : {};
          const names = SCRIPT_KEYS.filter(
            (k) => typeof scripts[k] === "string" && scripts[k].trim()
          );
          out.installScript = fact(names.length > 0, "registry packument scripts");
          out.scriptNames = names;
          if (names.length) {
            out.scriptBodies = Object.fromEntries(names.map((k) => [k, scripts[k]]));
          }
        } else {
          out.installScript = unknownFact(
            "registry returned neither a full packument nor npm's abbreviated form, so its " +
              "silence about install scripts means nothing"
          );
        }
      }
    }
    const created = p.time && p.time.created;
    if (typeof created === "string") {
      out.published = fact(created, "registry packument time.created");
    } else {
      out.published = unknownFact("registry packument has no time.created");
    }
    const vtime = p.time && p.time[entry.version];
    if (typeof vtime === "string") out.versionPublished = fact(vtime, "registry packument time");
  }

  return out;
}

/** package.json license can be a string, the legacy licenses array, or an object. */
export function normaliseLicenseField(doc) {
  if (typeof doc.license === "string") return doc.license;
  if (doc.license && typeof doc.license === "object" && typeof doc.license.type === "string") {
    return doc.license.type;
  }
  if (Array.isArray(doc.licenses)) {
    const types = doc.licenses
      .map((l) => (typeof l === "string" ? l : l && l.type))
      .filter((t) => typeof t === "string");
    if (types.length === 1) return types[0];
    if (types.length > 1) return `(${types.join(" OR ")})`;
  }
  return null;
}
