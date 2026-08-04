// Rendering findings for a human who has to decide something.
//
// The task this project comes from asks for "the justification line a reviewer needs". A finding
// that says "esbuild has a postinstall script" is not that line. The reviewer needs to know what
// the script is, where the claim came from, and what accepting it would mean, so every rendered
// finding carries the fact, its source, and the exact edit that accepts it.

const ICON = { block: "BLOCK ", review: "REVIEW", note: "note  " };

export function renderText(result, opts = {}) {
  const { findings, added, config, sources } = result;
  const lines = [];
  const color = opts.color ?? false;
  const bold = (s) => (color ? `[1m${s}[0m` : s);

  lines.push(bold(`install-gate: ${added.length} package(s) added or version-changed`));
  for (const s of sources) lines.push(`  source: ${s}`);
  lines.push("");

  if (findings.length === 0) {
    lines.push("  no findings");
  }

  const order = { block: 0, review: 1, note: 2 };
  const sorted = [...findings].sort(
    (a, b) => order[a.severity] - order[b.severity] || a.package.localeCompare(b.package)
  );

  for (const f of sorted) {
    lines.push(`${ICON[f.severity] ?? f.severity}  ${f.package}  [${f.rule}]`);
    lines.push(`        ${f.summary}`);
    if (f.detail) for (const l of wrap(f.detail, 92)) lines.push(`        ${l}`);
    if (f.evidence?.source) lines.push(`        source: ${f.evidence.source}`);
    if (f.evidence?.scripts) {
      for (const [k, v] of Object.entries(f.evidence.scripts)) {
        lines.push(`        ${k}: ${truncate(v, 140)}`);
      }
    }
    const accept = acceptanceLine(f, config);
    if (accept) for (const l of wrap(accept, 92)) lines.push(`        ${l}`);
    lines.push("");
  }

  const c = countBy(findings);
  lines.push(
    `${c.block} blocking, ${c.review} to review, ${c.note} noted` +
      (result.unknowns ? `, ${result.unknowns} fact(s) could not be established` : "")
  );
  return lines.join("\n");
}

export function acceptanceLine(f, config) {
  switch (f.rule) {
    case "install-script":
      return (
        `To accept: add {"name": ${JSON.stringify(f.name)}, "versions": [${JSON.stringify(
          f.version
        )}], "reason": "..."} to allowInstallScripts in ${config.configPath || ".install-gate.json"}. ` +
        "Pinning versions there means the next release of this package is reviewed again; " +
        "omitting them accepts every future release of it, including one published by whoever " +
        "next compromises the maintainer account."
      );
    case "license-class":
      return (
        `To accept: add ${JSON.stringify(f.evidence.class)} to licenseClasses with value "allow", ` +
        `or add ${JSON.stringify(f.evidence.ids?.[0] ?? "")} to allowLicenses for this identifier only.`
      );
    case "license-unparsed":
      return (
        "To accept: confirm the license text yourself, then add the exact string to allowLicenses. " +
        "This string could not be classified, so no tool has read it on your behalf."
      );
    case "new-package":
      return (
        "To accept: check the repository and the maintainer against the package you meant to " +
        "install, then lower minAgeDays or add the name to ignorePackages."
      );
    case "install-script-unknown":
    case "license-unknown":
    case "age-unknown":
      return (
        "This is not a clean result. It is an absent one. Install the dependencies and rerun with " +
        "--node-modules, or pass --registry to consult the registry, before treating it as fine."
      );
    case "source-disagreement":
      return (
        "Two sources describe the same package differently. The installed tarball is what runs, " +
        "so trust it over metadata, and treat the gap as worth understanding."
      );
    default:
      return null;
  }
}

export function renderMarkdown(result) {
  const { findings, added } = result;
  const c = countBy(findings);
  const out = [];
  out.push("### install-gate");
  out.push("");
  out.push(
    `${added.length} package(s) added or version-changed. ` +
      `**${c.block} blocking**, ${c.review} to review, ${c.note} noted.`
  );
  out.push("");
  if (!findings.length) {
    out.push("No findings.");
    return out.join("\n");
  }
  out.push("| severity | package | rule | what |");
  out.push("| --- | --- | --- | --- |");
  const order = { block: 0, review: 1, note: 2 };
  for (const f of [...findings].sort((a, b) => order[a.severity] - order[b.severity])) {
    out.push(
      `| ${f.severity} | \`${f.package}\` | ${f.rule} | ${escapePipes(f.summary)} |`
    );
  }
  out.push("");
  out.push("<details><summary>Justification lines</summary>");
  out.push("");
  for (const f of findings) {
    out.push(`**${f.package}** (${f.rule}): ${f.summary}`);
    if (f.detail) out.push(`> ${f.detail}`);
    if (f.evidence?.source) out.push(`> source: ${f.evidence.source}`);
    out.push("");
  }
  out.push("</details>");
  return out.join("\n");
}

export function countBy(findings) {
  const c = { block: 0, review: 0, note: 0 };
  for (const f of findings) if (c[f.severity] !== undefined) c[f.severity] += 1;
  return c;
}

function escapePipes(s) {
  return String(s).replace(/\|/g, "\\|");
}

function truncate(s, n) {
  const one = String(s).replace(/\s+/g, " ").trim();
  return one.length > n ? `${one.slice(0, n - 3)}...` : one;
}

export function wrap(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const out = [];
  let line = "";
  for (const w of words) {
    if (line && line.length + 1 + w.length > width) {
      out.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) out.push(line);
  return out;
}
