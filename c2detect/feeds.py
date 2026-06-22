"""c2detect.feeds — live threat-intel enrichment for C2DETECT (edge/air-gap ready).

C2DETECT's bundled signature DB catches *default* C2 fingerprints. This module
adds a second, complementary signal: cross-referencing an observation against
**real, public, keyless** abuse.ch threat-intel feeds so that a host already
*known* to be malicious is flagged even when its TLS profile has been customised
away from a documented default.

Two feeds from the bundled Cognis data-feed catalog are wired here (and only
these — c2detect's domain is ``threat-intel``):

  * ``feodo-c2`` — abuse.ch Feodo Tracker active botnet C2 IP blocklist
        https://feodotracker.abuse.ch/downloads/ipblocklist.json
        (Emotet / Dridex / TrickBot / QakBot / etc. C2 IPs)
  * ``sslbl``    — abuse.ch SSLBL malicious JA3 fingerprint blacklist
        https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
        (JA3 client fingerprints tied to malware families)

Edge / air-gap design (inherited from the bundled ``datafeeds`` module):
  * standard library only;
  * fetched over HTTPS, cached to disk (``COGNIS_FEEDS_CACHE``);
  * ``offline=True`` re-serves the cache and never touches the network;
  * ``datafeeds.py snapshot-export/-import`` sneakernets the cache into an
    air-gapped enclave.

Defensive / authorized-use intelligence only.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

# Bundled, sibling-imported so the package is self-contained on the edge.
from . import datafeeds

# The only catalog feeds relevant to c2detect's threat-intel domain.
RELEVANT_FEEDS: tuple[str, ...] = ("feodo-c2", "sslbl")

# The SSLBL JA3 blacklist lives in the catalog entry's ``ja3`` side-URL, not the
# primary cert-SHA1 ``url``. We fetch it under this synthetic cache id so it
# never collides with the cert feed and stays independently snapshottable.
_SSLBL_JA3_ID = "sslbl-ja3"


# --------------------------------------------------------------------------- #
# catalog helpers
# --------------------------------------------------------------------------- #
def catalog() -> dict:
    """The bundled data-feed catalog, filtered to c2detect's relevant feeds."""
    full = datafeeds.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f["id"] in RELEVANT_FEEDS]
    return {"_meta": full.get("_meta", {}), "feeds": feeds}


def list_relevant() -> list[dict]:
    """Catalog rows for the feeds c2detect consumes, with cache freshness."""
    rows = []
    for f in catalog()["feeds"]:
        # c2detect consumes the JA3 side-feed for sslbl, so report ITS freshness.
        cache_id = _SSLBL_JA3_ID if f["id"] == "sslbl" else f["id"]
        age = datafeeds.cached_age_hours(cache_id)
        rows.append({**f, "cached_age_hours": age})
    return rows


def _require_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise KeyError(
            f"{feed_id!r} is not a c2detect feed; choose from {RELEVANT_FEEDS}")


def update(feed_id: str) -> None:
    """Fetch + cache one relevant feed (online). For ``sslbl`` also caches the
    JA3 side-feed that c2detect actually consumes."""
    _require_relevant(feed_id)
    datafeeds.update(feed_id)
    if feed_id == "sslbl":
        _update_sslbl_ja3()


def update_all() -> None:
    for fid in RELEVANT_FEEDS:
        update(fid)


def _sslbl_ja3_url() -> str:
    for f in datafeeds.load_catalog().get("feeds", []):
        if f["id"] == "sslbl":
            return f.get("ja3", "")
    return ""


def _update_sslbl_ja3() -> None:
    """Cache the SSLBL JA3 CSV under a synthetic id using the shared cache."""
    url = _sslbl_ja3_url()
    if not url:
        return
    raw = datafeeds.fetch(url)
    data_path, meta_path = datafeeds._paths(_SSLBL_JA3_ID)
    data_path.write_bytes(raw)
    import time as _t
    meta_path.write_text(json.dumps({
        "feed": _SSLBL_JA3_ID, "url": url, "fetched_at": _t.time(),
        "bytes": len(raw), "format": "csv",
    }), encoding="utf-8")


# --------------------------------------------------------------------------- #
# feed -> indicator sets (parsed for matching)
# --------------------------------------------------------------------------- #
def feodo_c2_ips(*, offline: bool = False, max_age_hours: float = 6.0) -> dict[str, dict]:
    """Map of C2 IP -> entry (malware/port/country) from Feodo Tracker."""
    data = datafeeds.get("feodo-c2", offline=offline, max_age_hours=max_age_hours)
    out: dict[str, dict] = {}
    for e in data if isinstance(data, list) else data.get("ipblocklist", []):
        ip = str(e.get("ip_address", "")).strip()
        if ip:
            out[ip] = e
    return out


def sslbl_ja3(*, offline: bool = False, max_age_hours: float = 24.0) -> dict[str, dict]:
    """Map of malicious JA3 md5 -> {reason, first_seen, last_seen} from SSLBL.

    Reads the synthetic ``sslbl-ja3`` cache id. When not offline and the cache is
    stale/absent, refreshes the JA3 side-feed first.
    """
    age = datafeeds.cached_age_hours(_SSLBL_JA3_ID)
    if offline:
        if age is None:
            raise FileNotFoundError(
                "sslbl-ja3: nothing cached and offline=True (run `c2detect feeds update sslbl`)")
    elif age is None or age > max_age_hours:
        _update_sslbl_ja3()
    data_path, _ = datafeeds._paths(_SSLBL_JA3_ID)
    text = data_path.read_bytes().decode("utf-8", "replace")
    out: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4 and len(parts[0]) == 32:
            out[parts[0].lower()] = {
                "ja3": parts[0].lower(), "first_seen": parts[1],
                "last_seen": parts[2], "reason": parts[3],
            }
    return out


# --------------------------------------------------------------------------- #
# REAL enrichment: cross-reference an Observation against the live feeds.
# --------------------------------------------------------------------------- #
def enrich_observation(
    obs: Any,
    *,
    offline: bool = False,
    feodo: Optional[dict] = None,
    ja3bl: Optional[dict] = None,
) -> list[dict]:
    """Return threat-intel hits for one Observation (host IP and/or JA3).

    Each hit is a dict ``{source, severity, indicator, value, title, ...}``.
    Pass pre-loaded ``feodo``/``ja3bl`` maps to avoid re-reading the cache when
    enriching many observations (and to keep tests fully offline).
    """
    hits: list[dict] = []

    host = (getattr(obs, "host", "") or "").strip()
    if host:
        table = feodo if feodo is not None else feodo_c2_ips(offline=offline)
        e = table.get(host)
        if e:
            hits.append({
                "source": "feodo-c2",
                "severity": "critical",
                "indicator": "host_ip",
                "value": host,
                "malware": e.get("malware"),
                "c2_port": e.get("port"),
                "country": e.get("country"),
                "last_online": e.get("last_online"),
                "title": (f"Host {host} is a known active C2 IP "
                          f"({e.get('malware', 'unknown')}) per abuse.ch Feodo Tracker"),
                "reference": "https://feodotracker.abuse.ch/",
            })

    ja3 = (getattr(obs, "ja3", "") or "").strip().lower()
    if ja3:
        table = ja3bl if ja3bl is not None else sslbl_ja3(offline=offline)
        e = table.get(ja3)
        if e:
            hits.append({
                "source": "sslbl",
                "severity": "high",
                "indicator": "ja3",
                "value": ja3,
                "malware": e.get("reason"),
                "first_seen": e.get("first_seen"),
                "last_seen": e.get("last_seen"),
                "title": (f"JA3 {ja3} is on the abuse.ch SSLBL malicious-fingerprint "
                          f"blacklist ({e.get('reason', 'unknown')})"),
                "reference": "https://sslbl.abuse.ch/",
            })

    return hits


def enrich_observations(
    observations: Iterable[Any], *, offline: bool = False
) -> dict[int, list[dict]]:
    """Enrich many observations, loading each feed map exactly once."""
    feodo = feodo_c2_ips(offline=offline)
    ja3bl = sslbl_ja3(offline=offline)
    out: dict[int, list[dict]] = {}
    for i, obs in enumerate(observations):
        hits = enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
        if hits:
            out[i] = hits
    return out


# --------------------------------------------------------------------------- #
# CLI: `c2detect feeds list|update|get|enrich`
# --------------------------------------------------------------------------- #
def run_cli(args) -> int:
    sub = getattr(args, "feeds_cmd", None)

    if sub == "list":
        rows = list_relevant()
        for f in rows:
            age = f["cached_age_hours"]
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:10} {f.get('format',''):5} [{fresh:>10}]  {f['name']}")
            print(f"             {f.get('url','')}")
        print(f"\n{len(rows)} threat-intel feed(s) consumed by c2detect.")
        return 0

    if sub == "update":
        targets = args.feeds or list(RELEVANT_FEEDS)
        rc = 0
        for fid in targets:
            try:
                update(fid)
                print(f"  updated {fid}")
            except (KeyError, ConnectionError, OSError) as e:
                print(f"  {fid}: {e}", file=__import__("sys").stderr)
                rc = 1
        return rc

    if sub == "get":
        fid = args.feed
        try:
            _require_relevant(fid)
            if fid == "feodo-c2":
                data = feodo_c2_ips(offline=args.offline)
            else:
                data = sslbl_ja3(offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=__import__("sys").stderr)
            return 1
        print(json.dumps(data, indent=2)[:4000])
        print(f"\n{len(data)} indicator(s) in {fid}.")
        return 0

    print("usage: c2detect feeds {list|update|get} [...]",
          file=__import__("sys").stderr)
    return 2
