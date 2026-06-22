#!/usr/bin/env node
// JavaScript port of the c2detect CORE check: match TLS/network observations
// against a small bundled C2-framework signature DB (JARM / JA3 / port / URI).
// Passive only — reads files/JSON, never touches the network. Same JSON shape
// and family names as the Python reference.
import { readdirSync, statSync, readFileSync } from "fs";
import { join } from "path";

// Subset of the reference signature DB (public documented defaults).
export const SIGNATURES = [
  {
    family: "Cobalt Strike", severity: "critical",
    jarm: ["07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"],
    ja3: ["a0e9f5d64349fb13191bc781f81f42e1"],
    ports: [50050], uris: ["/submit.php", "/__utm.gif"],
  },
  {
    family: "Metasploit", severity: "high",
    ports: [4444, 8443], uris: ["/INITM", "/INITJM"],
  },
  {
    family: "Sliver", severity: "high",
    ports: [8888, 31337], uris: ["/health", "/staticfile"],
  },
];

const WEIGHTS = { jarm: 42, ja3: 24, uri: 16, port: 6 };
export const THRESHOLD = 35;

// Score one observation object against every signature.
export function scanObservation(obs) {
  const matches = [];
  for (const sig of SIGNATURES) {
    let conf = 0;
    const hits = [];
    if (obs.jarm && (sig.jarm || []).includes(obs.jarm)) { conf += WEIGHTS.jarm; hits.push("jarm"); }
    if (obs.ja3 && (sig.ja3 || []).includes(obs.ja3)) { conf += WEIGHTS.ja3; hits.push("ja3"); }
    for (const u of obs.uris || []) {
      if ((sig.uris || []).some((s) => u.includes(s))) { conf += WEIGHTS.uri; hits.push("uri"); break; }
    }
    if (obs.port && (sig.ports || []).includes(obs.port)) { conf += WEIGHTS.port; hits.push("port"); }
    conf = Math.min(conf, 100);
    if (conf >= THRESHOLD) matches.push({ family: sig.family, severity: sig.severity, confidence: conf, indicators: hits });
  }
  matches.sort((a, b) => b.confidence - a.confidence);
  return matches;
}

function obsFromRecord(r) {
  return {
    host: r.host || r.ip || r.dest_ip || "",
    jarm: r.jarm || "", ja3: r.ja3 || "",
    port: r.port || r.dest_port || r.dst_port || null,
    uris: r.uris || (r.uri ? [r.uri] : []),
  };
}

function walk(p) {
  try { return statSync(p).isDirectory()
    ? readdirSync(p).flatMap((f) => walk(join(p, f))) : [p]; }
  catch { return []; }
}

export function scan(target) {
  const results = [];
  for (const f of walk(target)) {
    let raw = "";
    try { raw = readFileSync(f, "utf8"); } catch { continue; }
    let recs = null;
    try { const d = JSON.parse(raw); recs = Array.isArray(d) ? d : (d.observations || [d]); }
    catch { continue; }
    for (const r of recs) {
      if (typeof r !== "object" || r === null) continue;
      const obs = obsFromRecord(r);
      const m = scanObservation(obs);
      if (m.length) results.push({ host: obs.host, matches: m });
    }
  }
  const matchCount = results.reduce((n, r) => n + r.matches.length, 0);
  return { tool: "c2detect", results, match_count: matchCount, score: matchCount };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(scan(process.argv[2] || "."), null, 2));
}
