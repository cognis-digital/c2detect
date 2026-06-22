"""C2DETECT correlation engine — cross-host C2 campaign clustering.

Defensive / authorized-triage use only. Standard library only, no network.

A single C2 detection is useful; a *cluster* of hosts sharing the same
operator infrastructure is what actually drives incident response. This module
takes a batch of observations (the same JSON/telemetry C2DETECT already
ingests) and groups hosts that share **infrastructure-level** indicators into
campaigns.

Why this matters (frank threat context)
----------------------------------------
Mature adversaries rotate domains and IPs constantly, but the things that are
expensive to rotate leak across their estate:

* **Server TLS fingerprints (JARM / JA4S / JA3S)** — a function of the TLS
  stack + listener config. A redirector farm spun from one Cobalt Strike /
  Sliver build tends to share the *same* JARM. Two unrelated IPs with the
  identical JARM are a strong "same kit, same config" pivot.
* **Certificate quirks (JA4X / shared CN, issuer, serial)** — self-signed certs
  minted from a default profile carry tell-tale subject/issuer strings. A reused
  cert serial across hosts is near-conclusive shared infrastructure.
* **Same C2 family at the same severity** — weaker on its own, but corroborating.
* **Identical default URI paths / beacon cadence** — a shared malleable profile.

C2DETECT does NOT attribute to a named actor and invents nothing: it only
clusters on indicators that two observations *literally share*, weights each
pivot by how hard it is to forge accidentally, and reports the evidence so an
analyst can adjudicate. This is detection / situational-awareness, not
targeting.

The output is a list of :class:`Campaign` objects (connected components over a
pivot graph), each ranked by a confidence score and carrying the exact shared
pivots that joined its members. Renders to table / JSON / Graphviz DOT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .core import (
    Observation,
    ScanResult,
    DEFAULT_THRESHOLD,
    Signature,
    scan_observation,
    SEVERITY_ORDER,
)

# ---------------------------------------------------------------------------
# Pivot weights — how strongly a *shared* value links two hosts. These are
# distinct from the single-host detection weights in core.WEIGHTS: here we care
# about how unlikely a coincidental match is across two independent hosts.
# A reused cert serial is near-conclusive; a shared port is nearly meaningless.
# ---------------------------------------------------------------------------
PIVOT_WEIGHTS: dict[str, int] = {
    "cert_serial": 50,   # reused x509 serial — near-conclusive shared infra
    "ja4x": 44,          # x509-derived cert fingerprint reuse
    "jarm": 40,          # shared server TLS fingerprint — same kit+config
    "ja4s": 38,          # shared server-response fingerprint
    "ja3s": 30,          # shared server-hello fingerprint
    "cert_cn": 30,       # shared certificate common-name / subject string
    "ja4": 26,           # shared client TLS fingerprint (implant build)
    "ja3": 22,
    "family": 18,        # same detected C2 family
    "uri": 12,           # shared default URI path / malleable profile
    "beacon": 12,        # near-identical beacon cadence
    "user_agent": 8,
    "port": 4,           # shared port — very weak on its own
}

# A campaign edge is only drawn when the joint pivot weight clears this floor,
# so a lone shared port (4) never fuses two hosts, but a shared JARM (40) does.
DEFAULT_EDGE_FLOOR = 24

# Confidence at/above which a multi-host campaign is reported.
DEFAULT_CAMPAIGN_THRESHOLD = 30

_CERT_SERIAL_TOKENS = ("serial", "sn=", "serialnumber")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _cert_serial(cert: str) -> str:
    """Best-effort extract a serial-number token from a cert text blob.

    Looks for ``serial: <hex>`` / ``serialNumber=<hex>`` style fragments. Pure
    string heuristic; returns "" when nothing serial-shaped is present.
    """
    import re

    low = cert or ""
    for m in re.finditer(
        r"serial(?:\s*number)?\s*[:=]\s*([0-9a-fA-F:]{4,})", low, re.IGNORECASE
    ):
        return m.group(1).replace(":", "").lower()
    return ""


def _cert_cn(cert: str) -> str:
    """Extract a CN= common-name token from a cert blob, lowercased."""
    import re

    # CN value runs until a field delimiter (, ; /) OR whitespace that precedes
    # another ``key:``/``key=`` token (e.g. "CN=foo serial: 1234"). Capturing
    # to a delimiter alone would swallow trailing "serial:" fragments when the
    # cert blob is space-separated rather than comma-separated.
    m = re.search(
        r"\bcn\s*=\s*([^,;/]+?)(?:\s*[,;/]|\s+\w+\s*[:=]|\s*$)",
        cert or "", re.IGNORECASE)
    if m:
        return m.group(1).strip().lower()
    return ""


@dataclass
class HostNode:
    """One host's correlation-relevant features, derived from an Observation."""

    host: str
    index: int
    obs: Observation
    family: str = ""          # top detected C2 family (if any)
    severity: str = "info"
    confidence: int = 0
    # Bucketed pivot values, by pivot class.
    pivots: dict[str, set[str]] = field(default_factory=dict)

    def pivot_values(self, klass: str) -> set[str]:
        return self.pivots.get(klass, set())


def _features(result: ScanResult, index: int) -> HostNode:
    """Reduce a ScanResult to the pivot features used for correlation."""
    obs = result.observation
    host = obs.host or f"obs[{index}]"
    node = HostNode(host=host, index=index, obs=obs)

    if result.top is not None:
        node.family = result.top.family
        node.severity = result.top.severity
        node.confidence = result.top.confidence

    p: dict[str, set[str]] = {}

    def put(klass: str, value: Any) -> None:
        v = _norm(value)
        if v:
            p.setdefault(klass, set()).add(v)

    put("jarm", obs.jarm)
    put("ja4s", obs.ja4s)
    put("ja3s", obs.ja3s)
    put("ja4", obs.ja4)
    put("ja3", obs.ja3)
    put("ja4x", obs.ja4x)
    put("user_agent", obs.user_agent)
    if obs.port is not None:
        put("port", obs.port)
    for u in obs.uris:
        put("uri", u)
    if node.family:
        put("family", node.family)
    if obs.cert:
        put("cert_serial", _cert_serial(obs.cert))
        put("cert_cn", _cert_cn(obs.cert))
    # Beacon cadence bucketed to nearest 5s so near-identical sleeps fuse.
    if obs.beacon_interval is not None:
        put("beacon", str(int(round(obs.beacon_interval / 5.0)) * 5))

    node.pivots = p
    return node


@dataclass
class SharedPivot:
    """A single indicator value shared by two (or more) hosts."""

    klass: str
    value: str
    weight: int

    def as_dict(self) -> dict[str, Any]:
        return {"class": self.klass, "value": self.value, "weight": self.weight}


def _shared_pivots(a: HostNode, b: HostNode) -> list[SharedPivot]:
    """Indicators literally shared between two hosts, weighted by forgeability."""
    out: list[SharedPivot] = []
    for klass, weight in PIVOT_WEIGHTS.items():
        common = a.pivot_values(klass) & b.pivot_values(klass)
        for v in sorted(common):
            out.append(SharedPivot(klass, v, weight))
    return out


def _edge_weight(pivots: Iterable[SharedPivot]) -> int:
    """Joint strength of an edge = sum of distinct pivot-class weights.

    Multiple values in the same class don't multiply (one shared JARM is as
    decisive as the JARM being shared); distinct strong classes reinforce.
    """
    by_class: dict[str, int] = {}
    for p in pivots:
        by_class[p.klass] = max(by_class.get(p.klass, 0), p.weight)
    return sum(by_class.values())


@dataclass
class Campaign:
    """A connected cluster of hosts sharing C2 infrastructure pivots."""

    cid: int
    members: list[HostNode]
    edges: list[tuple[str, str, list[SharedPivot]]]
    confidence: int
    severity: str
    families: list[str]
    # Aggregated shared pivots across the whole cluster, by class.
    shared: dict[str, list[str]]

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def hosts(self) -> list[str]:
        return [m.host for m in self.members]

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.cid,
            "size": self.size,
            "confidence": self.confidence,
            "severity": self.severity,
            "families": self.families,
            "hosts": self.hosts,
            "shared_pivots": self.shared,
            "edges": [
                {
                    "a": a,
                    "b": b,
                    "weight": _edge_weight(ps),
                    "pivots": [p.as_dict() for p in ps],
                }
                for (a, b, ps) in self.edges
            ],
        }


class _DSU:
    """Union-Find for connected-components clustering."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _worst_sev(sevs: Iterable[str]) -> str:
    best = "info"
    best_rank = SEVERITY_ORDER.get("info", 4)
    for s in sevs:
        r = SEVERITY_ORDER.get(s, 4)
        if r < best_rank:
            best_rank = r
            best = s
    return best


def correlate(
    results: list[ScanResult],
    edge_floor: int = DEFAULT_EDGE_FLOOR,
    campaign_threshold: int = DEFAULT_CAMPAIGN_THRESHOLD,
    include_singletons: bool = False,
) -> list[Campaign]:
    """Cluster scanned observations into shared-infrastructure campaigns.

    :param results: ScanResults (one per observation) from the core engine.
    :param edge_floor: minimum joint pivot weight to draw an edge between two
        hosts. Defaults so a single shared port (4) never fuses hosts but a
        shared JARM (40) does.
    :param campaign_threshold: minimum campaign confidence to report.
    :param include_singletons: when True, emit lone hosts as size-1 campaigns
        (useful for a complete inventory); off by default.
    :returns: campaigns sorted strongest-first.
    """
    nodes = [_features(r, i) for i, r in enumerate(results)]
    n = len(nodes)
    dsu = _DSU(n)

    # Pairwise edges. O(n^2) over the pivot features — fine for triage batches.
    edge_pivots: dict[tuple[int, int], list[SharedPivot]] = {}
    for i in range(n):
        for j in range(i + 1, n):
            piv = _shared_pivots(nodes[i], nodes[j])
            if not piv:
                continue
            if _edge_weight(piv) >= edge_floor:
                edge_pivots[(i, j)] = piv
                dsu.union(i, j)

    # Group node indices by component root.
    comps: dict[int, list[int]] = {}
    for i in range(n):
        comps.setdefault(dsu.find(i), []).append(i)

    campaigns: list[Campaign] = []
    cid = 0
    for _root, idxs in comps.items():
        if len(idxs) < 2 and not include_singletons:
            continue
        members = [nodes[i] for i in idxs]
        idx_set = set(idxs)
        edges = [
            (nodes[i].host, nodes[j].host, ps)
            for (i, j), ps in edge_pivots.items()
            if i in idx_set and j in idx_set
        ]
        # Aggregate shared pivots across the cluster.
        shared: dict[str, set[str]] = {}
        for (_a, _b, ps) in edges:
            for p in ps:
                shared.setdefault(p.klass, set()).add(p.value)
        shared_sorted = {k: sorted(v) for k, v in sorted(shared.items())}

        # Confidence: strongest single edge in the cluster + a corroboration
        # bonus for breadth (more members and more distinct strong pivot
        # classes => more confident it's one estate). Capped at 100.
        strongest = max((_edge_weight(ps) for (_a, _b, ps) in edges), default=0)
        distinct_strong = sum(
            1 for k in ("cert_serial", "ja4x", "jarm", "ja4s", "ja3s", "cert_cn")
            if k in shared
        )
        breadth_bonus = min(20, (len(members) - 2) * 4 + distinct_strong * 3)
        confidence = min(100, strongest + breadth_bonus)

        families = sorted({m.family for m in members if m.family})
        severity = _worst_sev(m.severity for m in members)

        if len(idxs) >= 2 and confidence < campaign_threshold:
            continue

        campaigns.append(
            Campaign(
                cid=cid,
                members=members,
                edges=edges,
                confidence=confidence if len(idxs) >= 2 else 0,
                severity=severity,
                families=families,
                shared=shared_sorted,
            )
        )
        cid += 1

    campaigns.sort(key=lambda c: (c.size, c.confidence), reverse=True)
    # Re-number after sorting so the strongest campaign is id 0.
    for new_id, c in enumerate(campaigns):
        c.cid = new_id
    return campaigns


def correlate_observations(
    observations: Iterable[Observation],
    threshold: int = DEFAULT_THRESHOLD,
    db: Iterable[Signature] | None = None,
    **kw: Any,
) -> list[Campaign]:
    """Convenience: scan then correlate raw Observations in one call."""
    sigs = tuple(db) if db is not None else None
    results = [scan_observation(o, threshold=threshold, db=sigs) for o in observations]
    return correlate(results, **kw)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def to_json(campaigns: list[Campaign]) -> dict[str, Any]:
    from .core import TOOL_NAME, TOOL_VERSION

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "mode": "correlate",
        "campaign_count": len(campaigns),
        "host_count": sum(c.size for c in campaigns),
        "campaigns": [c.as_dict() for c in campaigns],
    }


def to_table(campaigns: list[Campaign]) -> str:
    if not campaigns:
        return ("c2detect correlate: no shared-infrastructure campaigns "
                "found (no two hosts shared a pivot above the edge floor).")
    lines: list[str] = []
    for c in campaigns:
        fam = ", ".join(c.families) if c.families else "(unattributed)"
        lines.append(
            f"== Campaign #{c.cid}  [{c.severity.upper()}]  "
            f"confidence={c.confidence}  hosts={c.size}  families: {fam}"
        )
        for h in c.hosts:
            lines.append(f"   host: {h}")
        if c.shared:
            lines.append("   shared infrastructure pivots:")
            for klass in sorted(c.shared, key=lambda k: -PIVOT_WEIGHTS.get(k, 0)):
                vals = c.shared[klass]
                shown = ", ".join(vals[:3]) + (" ..." if len(vals) > 3 else "")
                lines.append(
                    f"     - {klass} (w={PIVOT_WEIGHTS.get(klass, 0)}): {shown}"
                )
        lines.append("")
    total = sum(c.size for c in campaigns)
    lines.append(
        f"c2detect: {len(campaigns)} campaign(s) clustering {total} host(s) "
        f"by shared C2 infrastructure."
    )
    return "\n".join(lines)


def to_dot(campaigns: list[Campaign]) -> str:
    """Graphviz DOT of the pivot graph — one subgraph per campaign.

    Render with: ``c2detect correlate obs.json --format dot | dot -Tsvg -o g.svg``
    """
    out: list[str] = ["graph c2campaigns {", "  graph [overlap=false];",
                       '  node [shape=box, style=rounded, fontname="monospace"];']
    sev_color = {
        "critical": "#b00020", "high": "#d9534f", "medium": "#f0ad4e",
        "low": "#5bc0de", "info": "#999999",
    }
    for c in campaigns:
        color = sev_color.get(c.severity, "#999999")
        out.append(f"  subgraph cluster_{c.cid} {{")
        fam = ", ".join(c.families) if c.families else "unattributed"
        out.append(
            f'    label="campaign #{c.cid} | {fam} | conf={c.confidence}";'
        )
        out.append(f'    color="{color}";')
        for h in c.hosts:
            out.append(f'    "{_dot_esc(h)}" [color="{color}"];')
        out.append("  }")
        for (a, b, ps) in c.edges:
            w = _edge_weight(ps)
            top = max(ps, key=lambda p: p.weight) if ps else None
            label = f"{top.klass}={w}" if top else str(w)
            penwidth = 1 + min(5, w // 20)
            out.append(
                f'  "{_dot_esc(a)}" -- "{_dot_esc(b)}" '
                f'[label="{label}", penwidth={penwidth}];'
            )
    out.append("}")
    return "\n".join(out)


def _dot_esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')
