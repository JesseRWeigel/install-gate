// The command line, and the exit code, which is the actual product.
//
//   0  no finding at or above --fail-on
//   1  at least one such finding
//   2  the gate could not run: bad arguments, unreadable lockfile, unparseable config
//
// 2 exists because a gate that exits 0 when it could not run is worse than no gate. CI would go
// green on a typo in a path.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseLockfile } from "./lockfile.js";
import { gather, indexNodeModules } from "./evidence.js";
import { loadConfig, evaluate, exitCodeFor, collapseUnknowns } from "./policy.js";
import { renderText, renderMarkdown, countBy } from "./report.js";

export const USAGE = `install-gate, a pre-merge check on dependency additions

  install-gate --lockfile package-lock.json [--base main] [options]

  --lockfile PATH     lockfile to inspect (default: package-lock.json)
  --base REF|PATH     git ref or file holding the previous lockfile. Without it every package
                      in the lockfile is treated as newly added.
  --config PATH       policy file (default: .install-gate.json when present)
  --node-modules      read the installed tarballs, which is the only local source that sees
                      the scripts that will actually run
  --registry URL      consult a registry for first-publish dates (network)
  --fail-on LEVEL     note | review | block   (default: block)
  --min-age-days N    flag packages first published within N days (default: 14)
  --on-unknown LEVEL  allow | note | review | block   (default: review)
  --format FORMAT     text | markdown | json   (default: text)
  --output PATH       also write the rendered report here
  --json-out PATH     write the full machine-readable result here
  --quiet             suppress the report on stdout
  --help              this text
`;

export function parseArgs(argv) {
  const opts = {
    lockfile: "package-lock.json",
    base: null,
    config: null,
    nodeModules: false,
    registry: null,
    failOn: "block",
    minAgeDays: null,
    onUnknown: null,
    format: "text",
    output: null,
    jsonOut: null,
    quiet: false,
    help: false,
    cwd: process.cwd(),
  };
  const need = (i, name) => {
    if (i + 1 >= argv.length) {
      const e = new Error(`${name} needs a value`);
      e.userError = true;
      throw e;
    }
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case "--lockfile": opts.lockfile = need(i, a); i += 1; break;
      case "--base": opts.base = need(i, a); i += 1; break;
      case "--config": opts.config = need(i, a); i += 1; break;
      case "--node-modules": opts.nodeModules = true; break;
      case "--registry": opts.registry = need(i, a); i += 1; break;
      case "--fail-on": opts.failOn = need(i, a); i += 1; break;
      case "--min-age-days": opts.minAgeDays = Number(need(i, a)); i += 1; break;
      case "--on-unknown": opts.onUnknown = need(i, a); i += 1; break;
      case "--format": opts.format = need(i, a); i += 1; break;
      case "--output": opts.output = need(i, a); i += 1; break;
      case "--json-out": opts.jsonOut = need(i, a); i += 1; break;
      case "--cwd": opts.cwd = need(i, a); i += 1; break;
      case "--quiet": opts.quiet = true; break;
      case "-h": case "--help": opts.help = true; break;
      default: {
        const e = new Error(`unknown argument ${a}`);
        e.userError = true;
        throw e;
      }
    }
  }
  if (!["text", "markdown", "json"].includes(opts.format)) {
    const e = new Error(`--format must be text, markdown or json (got ${opts.format})`);
    e.userError = true;
    throw e;
  }
  if (opts.minAgeDays !== null && !Number.isFinite(opts.minAgeDays)) {
    const e = new Error("--min-age-days must be a number");
    e.userError = true;
    throw e;
  }
  return opts;
}

function readBase(opts) {
  if (!opts.base) return null;
  const asPath = path.isAbsolute(opts.base) ? opts.base : path.join(opts.cwd, opts.base);
  if (fs.existsSync(asPath) && fs.statSync(asPath).isFile()) {
    return { text: fs.readFileSync(asPath, "utf8"), source: `file ${opts.base}` };
  }
  // Treat it as a git ref. If the lockfile did not exist at that ref, this is a first
  // introduction of the lockfile, which is a real state and not an error.
  const rel = path.relative(opts.cwd, path.resolve(opts.cwd, opts.lockfile)) || opts.lockfile;
  try {
    const text = execFileSync("git", ["show", `${opts.base}:${rel}`], {
      cwd: opts.cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { text, source: `git show ${opts.base}:${rel}` };
  } catch (err) {
    const msg = String(err.stderr || err.message);
    if (/exists on disk, but not in|does not exist in|path .* does not exist/i.test(msg)) {
      return { text: null, source: `${opts.base} has no ${rel}, so every package is new` };
    }
    const e = new Error(`could not read base ${opts.base}: ${msg.trim()}`);
    e.userError = true;
    throw e;
  }
}

async function fetchPackument(registry, name) {
  const url = `${registry.replace(/\/$/, "")}/${name.replace("/", "%2f")}`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`registry returned ${res.status} for ${name}`);
  return res.json();
}

export async function run(argv, io = {}) {
  const out = io.stdout ?? ((s) => process.stdout.write(s));
  const err = io.stderr ?? ((s) => process.stderr.write(s));

  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    err(`install-gate: ${e.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    out(USAGE);
    return 0;
  }

  try {
    const lockPath = path.resolve(opts.cwd, opts.lockfile);
    if (!fs.existsSync(lockPath)) {
      throw Object.assign(new Error(`lockfile not found: ${opts.lockfile}`), { userError: true });
    }
    const headText = fs.readFileSync(lockPath, "utf8");
    const head = parseLockfile(headText, lockPath);

    const sources = [`${opts.lockfile} (${head.kind} lockfileVersion ${head.version})`];

    const base = readBase(opts);
    let baseKeys = new Set();
    if (base && base.text !== null) {
      const parsedBase = parseLockfile(base.text, lockPath);
      baseKeys = new Set(parsedBase.packages.keys());
      sources.push(`base: ${base.source}, ${baseKeys.size} package(s)`);
    } else if (base) {
      sources.push(base.source);
    } else {
      sources.push("no --base given, so every package in the lockfile is treated as new");
    }

    const added = [...head.packages.values()].filter((e) => !baseKeys.has(e.key));

    // config
    let userConfig = {};
    let configPath = opts.config;
    if (!configPath) {
      const def = path.join(opts.cwd, ".install-gate.json");
      if (fs.existsSync(def)) configPath = def;
    }
    if (configPath) {
      const p = path.resolve(opts.cwd, configPath);
      if (!fs.existsSync(p)) {
        throw Object.assign(new Error(`config not found: ${configPath}`), { userError: true });
      }
      try {
        userConfig = JSON.parse(fs.readFileSync(p, "utf8"));
      } catch (e) {
        throw Object.assign(new Error(`config ${configPath} is not valid JSON: ${e.message}`), {
          userError: true,
        });
      }
      sources.push(`config: ${path.relative(opts.cwd, p) || configPath}`);
    }
    if (opts.minAgeDays !== null) userConfig.minAgeDays = opts.minAgeDays;
    if (opts.onUnknown !== null) userConfig.onUnknown = opts.onUnknown;
    const config = loadConfig(userConfig);
    config.configPath = configPath ? path.relative(opts.cwd, path.resolve(opts.cwd, configPath)) : null;

    let installedIndex = null;
    if (opts.nodeModules) {
      const nm = path.join(opts.cwd, "node_modules");
      if (!fs.existsSync(nm)) {
        throw Object.assign(
          new Error(
            "--node-modules was given but there is no node_modules directory. Run the install " +
              "first, or drop the flag and accept that install-script facts will be unknown."
          ),
          { userError: true }
        );
      }
      installedIndex = indexNodeModules(opts.cwd);
      sources.push(`node_modules: ${installedIndex.size} installed package.json files`);
      for (const e of installedIndex.errors) {
        err(`install-gate: could not parse ${e.path}: ${e.reason}\n`);
      }
    }
    if (opts.registry) sources.push(`registry: ${opts.registry}`);

    // Registry lookups, one per distinct name.
    const packuments = new Map();
    if (opts.registry) {
      const names = [...new Set(added.map((e) => e.name))];
      for (const name of names) {
        try {
          packuments.set(name, await fetchPackument(opts.registry, name));
        } catch (e) {
          // Recorded as an unknown fact rather than swallowed. The finding will say so.
          packuments.set(name, null);
          err(`install-gate: registry lookup failed for ${name}: ${e.message}\n`);
        }
      }
    }

    const evidence = added.map((e) =>
      gather(e, {
        root: opts.cwd,
        useNodeModules: opts.nodeModules,
        installedIndex,
        packument: packuments.get(e.name) || null,
      })
    );

    const findings = collapseUnknowns(evaluate(evidence, config));
    const unknowns = evidence.reduce(
      (n, ev) =>
        n +
        (ev.installScript.known ? 0 : 1) +
        (ev.license.known ? 0 : 1) +
        (config.minAgeDays > 0 && !ev.published.known ? 1 : 0),
      0
    );

    const result = {
      tool: "install-gate",
      lockfile: opts.lockfile,
      lockfileKind: head.kind,
      lockfileVersion: head.version,
      total: head.packages.size,
      added: added.map((e) => e.key),
      addedDetail: evidence.map((ev) => ({
        package: ev.key,
        installScript: ev.installScript,
        license: ev.license,
        published: ev.published,
        scriptNames: ev.scriptNames,
        notes: ev.notes,
      })),
      findings,
      counts: countBy(findings),
      unknowns,
      sources,
      config: {
        failOn: opts.failOn,
        minAgeDays: config.minAgeDays,
        onUnknown: config.onUnknown,
        configPath: config.configPath,
      },
    };

    const code = exitCodeFor(findings, opts.failOn);
    result.exitCode = code;

    let rendered;
    if (opts.format === "json") rendered = JSON.stringify(result, null, 2);
    else if (opts.format === "markdown") rendered = renderMarkdown(result);
    else rendered = renderText({ ...result, config }, { color: false });

    if (!opts.quiet) out(`${rendered}\n`);
    if (opts.output) fs.writeFileSync(path.resolve(opts.cwd, opts.output), `${rendered}\n`);
    if (opts.jsonOut) {
      fs.writeFileSync(path.resolve(opts.cwd, opts.jsonOut), `${JSON.stringify(result, null, 2)}\n`);
    }

    // Declared as one object so that scripts/check_action.py can read the exact set of names
    // and compare it against the outputs action.yml promises. Building the string inline meant
    // the names only existed inside a template literal, and the first version of that check
    // read one of them as "nblocking".
    const ghOutputs = {
      findings: findings.length,
      blocking: result.counts.block,
      review: result.counts.review,
      added: added.length,
      unknowns,
    };
    if (process.env.GITHUB_OUTPUT) {
      const body = Object.entries(ghOutputs)
        .map(([k, v]) => `${k}=${v}`)
        .join("\n");
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `${body}\n`);
    }
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${renderMarkdown(result)}\n`);
    }

    return code;
  } catch (e) {
    err(`install-gate: ${e.userError ? e.message : `${e.stack || e.message}`}\n`);
    return 2;
  }
}
