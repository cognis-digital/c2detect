// Rust port of the c2detect CORE check — fast, single binary, zero deps.
// Scores TLS/network observations against a bundled C2-framework signature DB
// (JARM / JA3 / port / URI). Passive only; no network.
use std::{env, fs};

pub const THRESHOLD: i32 = 35;

pub struct Signature {
    pub family: &'static str,
    pub severity: &'static str,
    pub jarm: &'static [&'static str],
    pub ja3: &'static [&'static str],
    pub ports: &'static [u32],
    pub uris: &'static [&'static str],
}

pub const SIGNATURES: &[Signature] = &[
    Signature {
        family: "Cobalt Strike",
        severity: "critical",
        jarm: &["07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"],
        ja3: &["a0e9f5d64349fb13191bc781f81f42e1"],
        ports: &[50050],
        uris: &["/submit.php", "/__utm.gif"],
    },
    Signature {
        family: "Metasploit",
        severity: "high",
        jarm: &[],
        ja3: &[],
        ports: &[4444, 8443],
        uris: &["/INITM", "/INITJM"],
    },
    Signature {
        family: "Sliver",
        severity: "high",
        jarm: &[],
        ja3: &[],
        ports: &[8888, 31337],
        uris: &["/health", "/staticfile"],
    },
];

#[derive(Default, Clone)]
pub struct Observation {
    pub host: String,
    pub jarm: String,
    pub ja3: String,
    pub port: u32,
    pub uris: Vec<String>,
}

pub struct Match {
    pub family: &'static str,
    pub severity: &'static str,
    pub confidence: i32,
}

/// Score one observation against the signature DB.
pub fn scan_observation(obs: &Observation) -> Vec<Match> {
    let mut out = Vec::new();
    for sig in SIGNATURES {
        let mut conf = 0;
        if !obs.jarm.is_empty() && sig.jarm.contains(&obs.jarm.as_str()) {
            conf += 42;
        }
        if !obs.ja3.is_empty() && sig.ja3.contains(&obs.ja3.as_str()) {
            conf += 24;
        }
        if obs.uris.iter().any(|u| sig.uris.iter().any(|s| u.contains(s))) {
            conf += 16;
        }
        if obs.port != 0 && sig.ports.contains(&obs.port) {
            conf += 6;
        }
        if conf > 100 {
            conf = 100;
        }
        if conf >= THRESHOLD {
            out.push(Match {
                family: sig.family,
                severity: sig.severity,
                confidence: conf,
            });
        }
    }
    out.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    out
}

// Tiny, dependency-free extraction of a few fields from a JSON-ish blob.
fn extract(blob: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let i = blob.find(&pat)? + pat.len();
    let rest = &blob[i..];
    let c = rest.find(':')? + 1;
    let v = rest[c..].trim_start();
    if let Some(stripped) = v.strip_prefix('"') {
        Some(stripped[..stripped.find('"')?].to_string())
    } else {
        let end = v.find(|ch: char| ch == ',' || ch == '}' || ch == '\n').unwrap_or(v.len());
        Some(v[..end].trim().to_string())
    }
}

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".into());
    let blob = fs::read_to_string(&target).unwrap_or_default();
    let mut obs = Observation::default();
    obs.jarm = extract(&blob, "jarm").unwrap_or_default();
    obs.ja3 = extract(&blob, "ja3").unwrap_or_default();
    obs.port = extract(&blob, "port").and_then(|p| p.parse().ok()).unwrap_or(0);
    obs.host = extract(&blob, "host").unwrap_or_default();
    let matches = scan_observation(&obs);
    println!(
        "{{\"tool\":\"c2detect\",\"host\":\"{}\",\"match_count\":{},\"score\":{}}}",
        obs.host,
        matches.len(),
        matches.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    const CS_JARM: &str = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";

    #[test]
    fn cobalt_strike_jarm() {
        let obs = Observation {
            jarm: CS_JARM.to_string(),
            ..Default::default()
        };
        let m = scan_observation(&obs);
        assert!(!m.is_empty());
        assert_eq!(m[0].family, "Cobalt Strike");
        assert!(m[0].confidence >= THRESHOLD);
    }

    #[test]
    fn clean_no_match() {
        let obs = Observation {
            host: "benign".into(),
            port: 443,
            ..Default::default()
        };
        assert!(scan_observation(&obs).is_empty());
    }

    #[test]
    fn weak_signals_below_threshold() {
        let obs = Observation {
            port: 50050,
            uris: vec!["/submit.php".into()],
            ..Default::default()
        };
        assert!(scan_observation(&obs).is_empty());
    }

    #[test]
    fn ja3_plus_port_plus_uri() {
        let obs = Observation {
            ja3: "a0e9f5d64349fb13191bc781f81f42e1".into(),
            port: 50050,
            uris: vec!["/submit.php".into()],
            ..Default::default()
        };
        let m = scan_observation(&obs);
        assert!(!m.is_empty());
        assert!(m[0].confidence >= THRESHOLD);
    }
}
