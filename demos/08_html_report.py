"""Scenario 8 - reporting: a self-contained HTML report for stakeholders.

**Audience:** anyone who has to *hand the result to a human* — IR leads, MSSP
client reports, ticket attachments.

Not every consumer reads JSON. c2detect renders a single self-contained HTML
file (no external CSS/JS/fonts — safe to email or drop in an air-gapped share)
summarising every observation, the matches, and the worst severity. This demo
generates the report for a multi-framework incident and verifies it is complete
and dependency-free.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations, to_html, worst_severity


def main() -> None:
    rule("HTML REPORT  -  one self-contained file for the stakeholder")

    records = load_observations("11-multi-framework-incident/observations.json")
    results = scan_observations(records, threshold=35)
    html = to_html(results)

    total = sum(r.count for r in results)
    worst = worst_severity(results) or "clean"

    print(f"\nObservations  : {len(results)}")
    print(f"Rule findings : {total}")
    print(f"Worst severity: {worst}")
    print(f"Report size   : {len(html):,} bytes\n")

    # The report must be self-contained: no http(s) asset references at all.
    external = ("http://" in html.replace("http://www.w3.org", "")
                or 'src="http' in html or '@import' in html)
    has_doctype = html.lstrip().lower().startswith("<!doctype html>")
    print(f"Valid <!doctype html>      : {has_doctype}")
    print(f"No external asset requests : {not external}")
    print(f"Every flagged host present : "
          f"{all((r.observation.host or '') in html for r in results if r.count)}")

    print("\nDeploy:")
    print("   c2detect scan incident.json --format html > report.html")
    print("\nEmail it, attach it to the ticket, open it on the air-gapped box — "
          "no CDN, no fonts, no network. Just the verdict.")


if __name__ == "__main__":
    main()
