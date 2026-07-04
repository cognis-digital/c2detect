"""Tests for campaign graph analytics (hub, density, linchpin, ATT&CK rollup)."""
from __future__ import annotations

from c2detect.core import scan_observations
from c2detect.correlate import correlate, campaign_analytics, analytics

CS = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def _campaign(n=3, jarm=CS):
    recs = [{"host": chr(ord("a") + i), "jarm": jarm} for i in range(n)]
    return correlate(scan_observations(recs))


class TestCampaignAnalytics:
    def test_clique_density_is_one(self):
        camps = _campaign(3)
        a = campaign_analytics(camps[0])
        assert a["density"] == 1.0
        assert a["size"] == 3
        assert a["edges"] == 3  # triangle

    def test_hub_and_degree(self):
        camps = _campaign(4)
        a = campaign_analytics(camps[0])
        assert a["hub_host"] in {"a", "b", "c", "d"}
        assert all(v == 3 for v in a["host_degree"].values())  # full clique

    def test_linchpin_is_jarm(self):
        a = campaign_analytics(_campaign(3)[0])
        assert a["linchpin_pivot"]["class"] == "jarm"
        assert a["linchpin_pivot"]["value"] == CS

    def test_pivot_histogram(self):
        a = campaign_analytics(_campaign(3)[0])
        assert "jarm" in a["pivot_class_histogram"]

    def test_attack_techniques_present(self):
        a = campaign_analytics(_campaign(3)[0])
        assert "T1071.001" in a["attack_techniques"]

    def test_families(self):
        a = campaign_analytics(_campaign(3)[0])
        assert "Cobalt Strike" in a["families"]


class TestPortfolioAnalytics:
    def test_rollup_shape(self):
        camps = _campaign(3)
        a = analytics(camps)
        assert a["campaign_count"] == 1
        assert a["host_count"] == 3
        assert a["largest_campaign"] == 3
        assert "Cobalt Strike" in a["family_prevalence"]
        assert len(a["campaigns"]) == 1

    def test_empty(self):
        a = analytics([])
        assert a["campaign_count"] == 0
        assert a["largest_campaign"] == 0
        assert a["campaigns"] == []


def test_public_api():
    import c2detect
    assert callable(c2detect.campaign_analytics)
    assert callable(c2detect.analytics)
