// Rust port of the Cognis scan logic — fast, single binary.
use std::{env, fs, path::Path};
fn walk(p: &Path, out: &mut Vec<String>) {
    if p.is_dir() {
        if let Ok(rd) = fs::read_dir(p) { for e in rd.flatten() { walk(&e.path(), out); } }
    } else if let Some(s) = p.to_str() { out.push(s.to_string()); }
}
fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".into());
    let rules = [("GEN-001","high","TODO"),("GEN-002","medium","FIXME"),("GEN-003","low","XXX")];
    let mut files = Vec::new();
    walk(Path::new(&target), &mut files);
    let mut n = 0;
    for f in &files {
        if let Ok(t) = fs::read_to_string(f) {
            for (id, sev, needle) in rules.iter() {
                if t.contains(needle) { println!("{} {} {}", id, sev, f); n += 1; }
            }
        }
    }
    println!("{{\"tool\":\"c2detect\",\"score\":{}}}", n);
}
