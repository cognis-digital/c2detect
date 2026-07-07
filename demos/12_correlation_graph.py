"""Scenario 12 - intel viz: render the campaign pivot graph as Graphviz DOT.

**Audience:** intel analysts who brief with pictures.

The correlation engine clusters hosts into campaigns; this demo renders that
cluster as Graphviz DOT — one subgraph per campaign, edges weighted and labelled
by the heaviest shared pivot — so ``dot -Tsvg`` turns a week of telemetry into a
one-page infrastructure map for the brief. It generates the DOT for the bundled
campaign fixture and verifies the graph is well-formed.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations
from c2detect.correlate import correlate, to_dot


def main() -> None:
    rule("CORRELATION GRAPH  -  campaigns as Graphviz DOT for the brief")

    records = load_observations("14-campaign-correlation/observations.json")
    results = scan_observations(records, threshold=35)
    campaigns = correlate(results)
    dot = to_dot(campaigns)

    lines = dot.splitlines()
    subgraphs = [l for l in lines if "subgraph cluster_" in l]
    edges = [l for l in lines if " -- " in l]

    print(f"\nCampaigns clustered : {len(campaigns)}")
    print(f"DOT subgraphs        : {len(subgraphs)} (one per campaign)")
    print(f"DOT edges            : {len(edges)} (one per shared-pivot link)\n")

    # Well-formed: opens `graph {`, closes `}`, every campaign has a subgraph.
    assert dot.startswith("graph c2campaigns {")
    assert dot.rstrip().endswith("}")
    assert len(subgraphs) == len(campaigns)

    print("First lines of the DOT:")
    for l in lines[:6]:
        print(f"   {l}")

    print("\nRender:")
    print("   c2detect correlate week.json --format dot | dot -Tsvg -o estate.svg")
    print("\nEach box is a host, each edge a literally-shared pivot (cert serial, "
          "JARM…). The picture is the adversary's estate, drawn from your own "
          "telemetry.")


if __name__ == "__main__":
    main()
