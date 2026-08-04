// Lockfile readers.
//
// The one thing this module must never do is guess. A lockfile format that carries no
// install-script information has to say "unknown", because a gate that reports "no install
// script" when it actually means "this file format cannot tell me" is worse than no gate.
// So every fact is a tri-state: true, false, or null for unknown, and every fact carries the
// name of the source it came from.

/**
 * @typedef {Object} Entry
 * @property {string} name
 * @property {string} version
 * @property {string} key            name@version
 * @property {string|null} resolved
 * @property {string|null} integrity
 * @property {boolean|null} hasInstallScript  null means the format cannot say
 * @property {string} installScriptSource
 * @property {string|null} license   null means the format did not record one
 * @property {string} licenseSource
 * @property {boolean} dev
 * @property {boolean} optional
 * @property {string|null} path      install path, npm lockfiles only
 */

const UNKNOWN = "format carries no such field";

function entry(fields) {
  return {
    name: fields.name,
    version: fields.version,
    key: `${fields.name}@${fields.version}`,
    resolved: fields.resolved ?? null,
    integrity: fields.integrity ?? null,
    hasInstallScript: fields.hasInstallScript ?? null,
    installScriptSource: fields.installScriptSource ?? UNKNOWN,
    license: fields.license ?? null,
    licenseSource: fields.licenseSource ?? UNKNOWN,
    dev: Boolean(fields.dev),
    optional: Boolean(fields.optional),
    path: fields.path ?? null,
  };
}

/** node_modules/a/node_modules/@scope/b  ->  @scope/b */
export function nameFromNpmPath(p) {
  const i = p.lastIndexOf("node_modules/");
  if (i === -1) return null;
  const rest = p.slice(i + "node_modules/".length);
  if (!rest) return null;
  return rest;
}

function parseNpm(doc, filename) {
  const version = doc.lockfileVersion;
  const packages = new Map();

  if (doc.packages && typeof doc.packages === "object") {
    // lockfileVersion 2 and 3. This is the only npm shape that records hasInstallScript
    // and license, and it records them because npm read the resolved tarball to build it.
    for (const [p, ent] of Object.entries(doc.packages)) {
      if (!p.startsWith("node_modules/")) continue; // "" is the root project, workspaces are links
      if (ent.link) continue; // a symlink into the repo, not a downloaded package
      const name = ent.name ?? nameFromNpmPath(p);
      if (!name || !ent.version) continue;
      const e = entry({
        name,
        version: ent.version,
        resolved: ent.resolved,
        integrity: ent.integrity,
        // npm writes hasInstallScript only when true, so an absent key means false here,
        // and that is a property of this format rather than an assumption we are making.
        hasInstallScript: ent.hasInstallScript === true,
        installScriptSource: `${filename} hasInstallScript`,
        license: typeof ent.license === "string" ? ent.license : null,
        licenseSource:
          typeof ent.license === "string"
            ? `${filename} license`
            : "npm recorded no license for this entry",
        dev: ent.dev,
        optional: ent.optional || ent.devOptional,
        path: p,
      });
      // Two paths can hold the same name@version. Keep the first, they are the same tarball.
      if (!packages.has(e.key)) packages.set(e.key, e);
    }
    return { kind: "npm", version, packages, filename };
  }

  if (doc.dependencies && typeof doc.dependencies === "object") {
    // lockfileVersion 1. No install-script field, no license field, so everything is unknown.
    const walk = (deps, dev) => {
      for (const [name, ent] of Object.entries(deps)) {
        if (!ent || typeof ent !== "object" || !ent.version) continue;
        const e = entry({
          name,
          version: ent.version,
          resolved: ent.resolved,
          integrity: ent.integrity,
          hasInstallScript: null,
          installScriptSource: "lockfileVersion 1 has no hasInstallScript field",
          license: null,
          licenseSource: "lockfileVersion 1 has no license field",
          dev: dev || ent.dev,
          optional: ent.optional,
        });
        if (!packages.has(e.key)) packages.set(e.key, e);
        if (ent.dependencies) walk(ent.dependencies, dev || Boolean(ent.dev));
      }
    };
    walk(doc.dependencies, false);
    return { kind: "npm", version: version ?? 1, packages, filename };
  }

  return { kind: "npm", version: version ?? null, packages, filename };
}

// pnpm-lock.yaml, read with a targeted scanner rather than a YAML parser.
//
// Only the `packages:` block is read, and only its keys, which are `name@version` strings.
// pnpm lockfile 9 records no install-script flag and no license, so every entry from here is
// unknown on both. Lockfile 5 and 6 had `requiresBuild`, which is read when present.
function parsePnpm(text, filename) {
  const packages = new Map();
  const lines = text.split(/\r?\n/);
  let version = null;
  let inPackages = false;
  let current = null;

  const flush = () => {
    if (!current) return;
    if (!packages.has(current.key)) packages.set(current.key, current);
    current = null;
  };

  for (const line of lines) {
    const lv = /^lockfileVersion:\s*'?([\d.]+)'?/.exec(line);
    if (lv) version = lv[1];
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (!inPackages) continue;
    if (/^\S/.test(line)) {
      // any other top level key ends the block
      flush();
      inPackages = false;
      continue;
    }
    const key = /^ {2}(?:'([^']+)'|"([^"]+)"|([^\s:][^:]*)):\s*$/.exec(line);
    if (key) {
      flush();
      const raw = key[1] ?? key[2] ?? key[3];
      const parsed = parsePnpmKey(raw);
      if (parsed) {
        current = entry({
          name: parsed.name,
          version: parsed.version,
          hasInstallScript: null,
          installScriptSource: `${filename} records no install-script flag`,
          license: null,
          licenseSource: `${filename} records no license`,
        });
      }
      continue;
    }
    if (current && /^ {4}requiresBuild:\s*true\b/.test(line)) {
      current.hasInstallScript = true;
      current.installScriptSource = `${filename} requiresBuild`;
    }
  }
  flush();
  return { kind: "pnpm", version, packages, filename };
}

/** '@scope/pkg@1.2.3(peer@4)' or '/pkg/1.2.3' (v5) or 'pkg@1.2.3' */
export function parsePnpmKey(raw) {
  let s = raw;
  if (s.startsWith("/")) {
    // lockfile 5 style: /name/version_peer  or /@scope/name/version
    s = s.slice(1);
    const at = s.lastIndexOf("/");
    if (at === -1) return null;
    const name = s.slice(0, at);
    let version = s.slice(at + 1);
    version = version.split("_")[0].split("(")[0];
    if (!name || !version) return null;
    return { name, version };
  }
  const paren = s.indexOf("(");
  if (paren !== -1) s = s.slice(0, paren);
  const at = s.lastIndexOf("@");
  if (at <= 0) return null;
  const name = s.slice(0, at);
  const version = s.slice(at + 1);
  if (!name || !version || !/^\d/.test(version)) return null;
  return { name, version };
}

// yarn.lock v1. Blocks separated by blank lines, keyed by one or more quoted specs.
function parseYarn(text, filename) {
  const packages = new Map();
  const lines = text.split(/\r?\n/);
  let specs = [];
  let version = null;
  let resolved = null;
  let integrity = null;

  const flush = () => {
    if (specs.length && version) {
      const name = specNames(specs)[0];
      if (name) {
        const e = entry({
          name,
          version,
          resolved,
          integrity,
          hasInstallScript: null,
          installScriptSource: `${filename} records no install-script flag`,
          license: null,
          licenseSource: `${filename} records no license`,
        });
        if (!packages.has(e.key)) packages.set(e.key, e);
      }
    }
    specs = [];
    version = null;
    resolved = null;
    integrity = null;
  };

  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      flush();
      specs = line.replace(/:\s*$/, "").split(/,\s*/).map((s) => s.trim());
      continue;
    }
    let m = /^ {2}version:?\s+"?([^"\s]+)"?/.exec(line);
    if (m) version = m[1];
    m = /^ {2}resolved:?\s+"?([^"\s]+)"?/.exec(line);
    if (m) resolved = m[1];
    m = /^ {2}integrity:?\s+"?([^"\s]+)"?/.exec(line);
    if (m) integrity = m[1];
  }
  flush();
  return { kind: "yarn", version: 1, packages, filename };
}

/** '"@scope/pkg@^1.0.0"' -> '@scope/pkg' */
export function specNames(specs) {
  const out = [];
  for (const raw of specs) {
    const s = raw.replace(/^["']|["']$/g, "");
    const at = s.lastIndexOf("@");
    if (at <= 0) continue;
    out.push(s.slice(0, at));
  }
  return out;
}

/**
 * @param {string} text file contents
 * @param {string} filename used for provenance strings and format detection
 */
export function parseLockfile(text, filename) {
  const base = filename.split("/").pop();
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json" || base.endsWith(".json")) {
    let doc;
    try {
      doc = JSON.parse(text);
    } catch (err) {
      throw new Error(`${filename} is not valid JSON: ${err.message}`);
    }
    return parseNpm(doc, base);
  }
  if (base.startsWith("pnpm-lock")) return parsePnpm(text, base);
  if (base.startsWith("yarn.lock")) return parseYarn(text, base);
  throw new Error(
    `unrecognised lockfile name ${base}. Supported: package-lock.json, npm-shrinkwrap.json, ` +
      `pnpm-lock.yaml, yarn.lock`
  );
}
