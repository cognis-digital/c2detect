#!/usr/bin/env node
// TypeScript port of the c2detect CORE check. Passive only; no network.
// Same family names / JSON shape as the Python reference.
import { readFileSync } from "fs";

export interface Signature {
  family: string;
  severity: string;
  jarm?: string[];
  ja3?: string[];
  ports?: number[];
  uris?: string[];
}

export interface Observation {
  host?: string;
  jarm?: string;
  ja3?: string;
  port?: number | null;
  uris?: string[];
}

export interface Match {
  family: string;
  severity: string;
  confidence: number;
  indicators: string[];
}

export const THRESHOLD = 35;
const WEIGHTS = { jarm: 42, ja3: 24, uri: 16, port: 6 };

export const SIGNATURES: Signature[] = [
  {
    family: "Cobalt Strike",
    severity: "critical",
    jarm: ["07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"],
    ja3: ["a0e9f5d64349fb13191bc781f81f42e1"],
    ports: [50050],
    uris: ["/submit.php", "/__utm.gif"],
  },
  { family: "Metasploit", severity: "high", ports: [4444, 8443], uris: ["/INITM", "/INITJM"] },
  { family: "Sliver", severity: "high", ports: [8888, 31337], uris: ["/health", "/staticfile"] },
];

export function scanObservation(obs: Observation): Match[] {
  const matches: Match[] = [];
  for (const sig of SIGNATURES) {
    let conf = 0;
    const hits: string[] = [];
    if (obs.jarm && (sig.jarm ?? []).includes(obs.jarm)) { conf += WEIGHTS.jarm; hits.push("jarm"); }
    if (obs.ja3 && (sig.ja3 ?? []).includes(obs.ja3)) { conf += WEIGHTS.ja3; hits.push("ja3"); }
    if ((obs.uris ?? []).some((u) => (sig.uris ?? []).some((s) => u.includes(s)))) {
      conf += WEIGHTS.uri; hits.push("uri");
    }
    if (obs.port && (sig.ports ?? []).includes(obs.port)) { conf += WEIGHTS.port; hits.push("port"); }
    if (conf > 100) conf = 100;
    if (conf >= THRESHOLD) matches.push({ family: sig.family, severity: sig.severity, confidence: conf, indicators: hits });
  }
  return matches.sort((a, b) => b.confidence - a.confidence);
}

export function scanFile(path: string): { tool: string; results: any[]; match_count: number } {
  let recs: any[] = [];
  try {
    const d = JSON.parse(readFileSync(path, "utf8"));
    recs = Array.isArray(d) ? d : d.observations ?? [d];
  } catch {
    recs = [];
  }
  const results: any[] = [];
  let matchCount = 0;
  for (const r of recs) {
    if (typeof r !== "object" || r === null) continue;
    const obs: Observation = {
      host: r.host ?? r.ip ?? "",
      jarm: r.jarm ?? "",
      ja3: r.ja3 ?? "",
      port: r.port ?? r.dest_port ?? null,
      uris: r.uris ?? (r.uri ? [r.uri] : []),
    };
    const m = scanObservation(obs);
    if (m.length) { results.push({ host: obs.host, matches: m }); matchCount += m.length; }
  }
  return { tool: "c2detect", results, match_count: matchCount };
}

if (process.argv[1] && process.argv[1].endsWith("index.ts")) {
  console.log(JSON.stringify(scanFile(process.argv[2] || ""), null, 2));
}
