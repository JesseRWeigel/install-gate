// License classification.
//
// The naive version of this is a substring search for "GPL". It is wrong in both directions on
// real data. "(MPL-2.0 OR Apache-2.0)" contains MPL but you may take the Apache option, and
// "LGPL-3.0-or-later" contains GPL but is a different obligation from GPL-3.0. Both of those
// appear in the trees this project was measured against, so the expression is parsed rather
// than searched.

export const CLASSES = [
  "public-domain",
  "permissive",
  "weak-copyleft",
  "strong-copyleft",
  "network-copyleft",
  "proprietary",
  "nonstandard",
  "unknown",
];

// Ordered permissive to restrictive. An OR takes the least restrictive branch because the
// licensee chooses. An AND takes the most restrictive because every obligation applies.
const RANK = {
  "public-domain": 0,
  permissive: 1,
  "weak-copyleft": 2,
  "strong-copyleft": 3,
  "network-copyleft": 4,
  proprietary: 5,
  nonstandard: 6,
  unknown: 7,
};

const PUBLIC_DOMAIN = new Set(["CC0-1.0", "Unlicense", "0BSD", "MIT-0", "WTFPL", "BlueOak-1.0.0"]);

const PERMISSIVE = new Set([
  "MIT", "ISC", "Apache-2.0", "Apache-1.1", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
  "BSD-4-Clause", "Python-2.0", "PSF-2.0", "Zlib", "libpng-2.0", "X11", "AFL-2.1", "AFL-3.0",
  "Artistic-2.0", "BSL-1.0", "CC-BY-3.0", "CC-BY-4.0", "OFL-1.1", "Ruby", "UPL-1.0",
  "Unicode-DFS-2016", "Unicode-3.0", "W3C", "curl", "NTP", "JSON",
]);

const WEAK_COPYLEFT = new Set([
  "MPL-1.1", "MPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only",
  "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-2.1", "LGPL-3.0",
  "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "EUPL-1.1", "EUPL-1.2",
  "Apache-2.0-with-LLVM-exception", "OSL-3.0",
]);

const STRONG_COPYLEFT = new Set([
  "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
  "GPL-1.0-only", "GPL-1.0-or-later", "CC-BY-SA-4.0", "CC-BY-SA-3.0",
]);

const NETWORK_COPYLEFT = new Set([
  "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-1.0-only", "AGPL-1.0-or-later",
  "SSPL-1.0", "OSL-3.0-network", "EUPL-1.2-network",
]);

// Non-commercial and no-derivatives Creative Commons variants are not open source licences at
// all, so they are treated as proprietary rather than as any flavour of copyleft.
const PROPRIETARY = new Set([
  "UNLICENSED", "CC-BY-NC-4.0", "CC-BY-NC-3.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0",
  "Commercial", "Proprietary",
]);

function classifyId(id) {
  const bare = id.replace(/\+$/, "");
  // A GPL exception, for example "GPL-2.0-with-classpath-exception", relaxes linking but the
  // base licence still governs, so classify on the base identifier.
  const withExc = /^(.*?)\s+WITH\s+(.*)$/i.exec(bare);
  const core = withExc ? withExc[1].trim() : bare;

  for (const [set, cls] of [
    [PUBLIC_DOMAIN, "public-domain"],
    [PERMISSIVE, "permissive"],
    [WEAK_COPYLEFT, "weak-copyleft"],
    [STRONG_COPYLEFT, "strong-copyleft"],
    [NETWORK_COPYLEFT, "network-copyleft"],
    [PROPRIETARY, "proprietary"],
  ]) {
    if (set.has(core)) return cls;
    for (const known of set) {
      if (known.toLowerCase() === core.toLowerCase()) return cls;
    }
  }
  return "nonstandard";
}

/**
 * Tokenise and evaluate an SPDX expression.
 * Returns { class, ids, expression, parsed } where parsed is false when the string is not an
 * SPDX expression at all, for example "SIL OPEN FONT LICENSE" or "SEE LICENSE IN LICENSE.txt".
 */
export function classifyLicense(raw) {
  if (raw === null || raw === undefined || String(raw).trim() === "") {
    return { class: "unknown", ids: [], expression: null, parsed: false };
  }
  const expression = String(raw).trim();

  if (/^SEE LICEN[CS]E IN /i.test(expression)) {
    return { class: "nonstandard", ids: [], expression, parsed: false };
  }

  const tokens = tokenise(expression);
  if (!tokens) return { class: "nonstandard", ids: [], expression, parsed: false };

  let node;
  const pos = { i: 0 };
  try {
    node = parseExpr(tokens, pos);
    // Every token has to be consumed. Without this check "SIL OPEN FONT LICENSE" parsed as the
    // single identifier "SIL" and the other three words were silently dropped, which is the
    // shape of bug that turns a real license string into a confident wrong answer.
    if (pos.i !== tokens.length) throw new Error("trailing tokens");
  } catch {
    return { class: "nonstandard", ids: [], expression, parsed: false };
  }
  const ids = [];
  const cls = evaluate(node, ids);
  return { class: cls, ids, expression, parsed: true };
}

function tokenise(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) {
      i += 1;
      continue;
    }
    if (c === "(" || c === ")") {
      out.push({ t: c });
      i += 1;
      continue;
    }
    let j = i;
    while (j < s.length && !/[\s()]/.test(s[j])) j += 1;
    const word = s.slice(i, j);
    i = j;
    const up = word.toUpperCase();
    // npm registry data contains lowercase "or", which SPDX does not allow. It is accepted
    // here because refusing it would mean classifying real packages as unparseable.
    if (up === "OR" || up === "AND") out.push({ t: up });
    else if (up === "WITH") out.push({ t: "WITH" });
    else out.push({ t: "id", v: word });
  }
  return out.length ? out : null;
}

function parseExpr(tokens, pos) {
  let left = parseAnd(tokens, pos);
  while (pos.i < tokens.length && tokens[pos.i].t === "OR") {
    pos.i += 1;
    const right = parseAnd(tokens, pos);
    left = { op: "OR", left, right };
  }
  return left;
}

function parseAnd(tokens, pos) {
  let left = parseAtom(tokens, pos);
  while (pos.i < tokens.length && tokens[pos.i].t === "AND") {
    pos.i += 1;
    const right = parseAtom(tokens, pos);
    left = { op: "AND", left, right };
  }
  return left;
}

function parseAtom(tokens, pos) {
  const tok = tokens[pos.i];
  if (!tok) throw new Error("unexpected end of expression");
  if (tok.t === "(") {
    pos.i += 1;
    const inner = parseExpr(tokens, pos);
    if (!tokens[pos.i] || tokens[pos.i].t !== ")") throw new Error("unbalanced parenthesis");
    pos.i += 1;
    return inner;
  }
  if (tok.t !== "id") throw new Error(`unexpected token ${tok.t}`);
  pos.i += 1;
  let id = tok.v;
  if (tokens[pos.i] && tokens[pos.i].t === "WITH") {
    pos.i += 1;
    const exc = tokens[pos.i];
    if (!exc || exc.t !== "id") throw new Error("WITH needs an exception identifier");
    pos.i += 1;
    id = `${id} WITH ${exc.v}`;
  }
  return { id };
}

function evaluate(node, ids) {
  if (node.id !== undefined) {
    ids.push(node.id);
    return classifyId(node.id);
  }
  const a = evaluate(node.left, ids);
  const b = evaluate(node.right, ids);
  if (node.op === "OR") return RANK[a] <= RANK[b] ? a : b;
  return RANK[a] >= RANK[b] ? a : b;
}

export const _internals = { classifyId, RANK };
