"""datafeeds — edge/air-gap-deployable ingestion for the Cognis data-feed catalog.

Real, recent, mostly-keyless intelligence feeds (CISA KEV, EPSS, OSV, NVD, MITRE
ATT&CK STIX, abuse.ch C2/IOC, NIST OSCAL 800-53, OFAC, GDELT, OpenSky, cloud IP
ranges) fetched over HTTPS, cached to disk, and re-served **offline** so a tool
keeps working on disconnected / military / edge gear.

Design for the edge:
  * Standard library only (urllib) — no pip deps, drops into any stdlib tool.
  * Disk cache (``COGNIS_FEEDS_CACHE`` env, default ~/.cache/cognis-feeds) with
    per-feed freshness metadata.
  * ``offline=True`` serves cache only and never touches the network.
  * ``snapshot_export``/``snapshot_import`` tar the cache for sneakernet transfer
    to an air-gapped enclave.

Defensive / authorized-use intelligence only.

CLI:
    python datafeeds.py list [--domain vuln]
    python datafeeds.py update cisa-kev epss            # fetch + cache
    python datafeeds.py get cisa-kev [--offline]        # print cached/fetched
    python datafeeds.py snapshot-export feeds.tar.gz    # for air-gap transfer
    python datafeeds.py snapshot-import feeds.tar.gz
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Optional

_UA = "Mozilla/5.0 (cognis-datafeeds; +https://github.com/cognis-digital)"
_HERE = Path(__file__).resolve().parent
_CATALOG_PATH = _HERE / "data_feeds_2026.json"


def cache_dir() -> Path:
    d = Path(os.environ.get("COGNIS_FEEDS_CACHE", Path.home() / ".cache" / "cognis-feeds"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_catalog(path: Optional[str] = None) -> dict:
    p = Path(path) if path else _CATALOG_PATH
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"feeds": []}


def _catalog_feeds(catalog: Optional[dict] = None) -> dict:
    cat = catalog or load_catalog()
    return {f["id"]: f for f in cat.get("feeds", [])}


def list_feeds(domain: Optional[str] = None, catalog: Optional[dict] = None) -> list[dict]:
    feeds = list(_catalog_feeds(catalog).values())
    if domain:
        feeds = [f for f in feeds if f.get("domain") == domain]
    return feeds


# --------------------------------------------------------------------------- #
# fetch + cache
# --------------------------------------------------------------------------- #
def fetch(url: str, *, method: str = "GET", data: Optional[bytes] = None,
          timeout: float = 30.0, retries: int = 2) -> bytes:
    """Fetch raw bytes over HTTP(S) with a UA + simple retry. Online only."""
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, method=method,
                                         headers={"User-Agent": _UA, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:  # pragma: no cover - network
            last = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise ConnectionError(f"fetch failed for {url}: {last}")


def _paths(feed_id: str) -> tuple[Path, Path]:
    base = cache_dir() / feed_id
    return base.with_suffix(".data"), base.with_suffix(".meta.json")


def cached_age_hours(feed_id: str) -> Optional[float]:
    _, meta = _paths(feed_id)
    if not meta.exists():
        return None
    try:
        ts = json.loads(meta.read_text(encoding="utf-8")).get("fetched_at", 0)
    except ValueError:
        return None
    return (time.time() - ts) / 3600.0


def update(feed_id: str, *, catalog: Optional[dict] = None,
           query: Optional[dict] = None) -> Path:
    """Fetch a catalogued feed and write it (+meta) to the cache. Returns the data path."""
    feeds = _catalog_feeds(catalog)
    if feed_id not in feeds:
        raise KeyError(f"unknown feed {feed_id!r}; see list_feeds()")
    f = feeds[feed_id]
    url, method = f["url"], f.get("method", "GET")
    body = json.dumps(query).encode() if (method == "POST" and query) else None
    raw = fetch(url, method=method, data=body)
    data_path, meta_path = _paths(feed_id)
    data_path.write_bytes(raw)
    meta_path.write_text(json.dumps({
        "feed": feed_id, "url": url, "fetched_at": time.time(),
        "bytes": len(raw), "format": f.get("format", "raw"),
    }), encoding="utf-8")
    return data_path


def get(feed_id: str, *, offline: bool = False, max_age_hours: float = 24.0,
        catalog: Optional[dict] = None, query: Optional[dict] = None) -> Any:
    """Return parsed feed content (json/stix/oscal -> dict; csv/text -> str).

    Uses the cache when fresh (or when ``offline``); otherwise refreshes it.
    Raises FileNotFoundError if ``offline`` and nothing is cached.
    """
    feeds = _catalog_feeds(catalog)
    fmt = feeds.get(feed_id, {}).get("format", "raw")
    data_path, _ = _paths(feed_id)
    age = cached_age_hours(feed_id)

    if offline:
        if age is None:
            raise FileNotFoundError(f"{feed_id}: nothing cached and offline=True")
    elif age is None or age > max_age_hours:
        update(feed_id, catalog=catalog, query=query)

    raw = data_path.read_bytes()
    if fmt in ("json", "stix", "oscal"):
        return json.loads(raw)
    return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# air-gap snapshot (sneakernet the cache into a disconnected enclave)
# --------------------------------------------------------------------------- #
def snapshot_export(path: str) -> int:
    """Tar the feed cache *flat* (filenames at the archive root) so it imports
    into any cache dir regardless of its name — for sneakernet to an air gap."""
    files = list(cache_dir().glob("*.data")) + list(cache_dir().glob("*.meta.json"))
    with tarfile.open(path, "w:gz") as tar:
        for fp in files:
            tar.add(fp, arcname=fp.name)
    return sum(1 for _ in cache_dir().glob("*.data"))


def snapshot_import(path: str) -> int:
    """Extract a flat snapshot directly into the current cache dir (name-independent)."""
    dest = cache_dir()
    with tarfile.open(path, "r:gz") as tar:
        for m in tar.getmembers():
            name = os.path.basename(m.name)
            if not m.isfile() or not name or name.startswith("."):
                continue
            with tar.extractfile(m) as src:  # noqa: S202 - basename-only, no path traversal
                (dest / name).write_bytes(src.read())
    return sum(1 for _ in dest.glob("*.data"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="datafeeds", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd")
    pl = sub.add_parser("list"); pl.add_argument("--domain")
    pu = sub.add_parser("update"); pu.add_argument("feeds", nargs="+")
    pg = sub.add_parser("get"); pg.add_argument("feed"); pg.add_argument("--offline", action="store_true")
    pe = sub.add_parser("snapshot-export"); pe.add_argument("path")
    pi = sub.add_parser("snapshot-import"); pi.add_argument("path")
    args = p.parse_args(argv)

    if args.cmd == "list":
        for f in list_feeds(args.domain):
            age = cached_age_hours(f["id"])
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:28} {f.get('domain',''):13} [{fresh}]  {f['name']}")
        return 0
    if args.cmd == "update":
        for fid in args.feeds:
            try:
                pth = update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr)
        return 0
    if args.cmd == "get":
        try:
            data = get(args.feed, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr); return 1
        print(json.dumps(data, indent=2)[:4000] if isinstance(data, (dict, list)) else data[:4000])
        return 0
    if args.cmd == "snapshot-export":
        print(f"exported {snapshot_export(args.path)} feed(s) -> {args.path}"); return 0
    if args.cmd == "snapshot-import":
        print(f"imported {snapshot_import(args.path)} feed(s) from {args.path}"); return 0
    p.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
