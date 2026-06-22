package main

import "testing"

const csJARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

func TestCobaltStrikeJARM(t *testing.T) {
	m := ScanObservation(Observation{JARM: csJARM})
	if len(m) == 0 || m[0].Family != "Cobalt Strike" {
		t.Fatalf("expected Cobalt Strike, got %#v", m)
	}
	if m[0].Confidence < Threshold {
		t.Fatalf("confidence %d below threshold", m[0].Confidence)
	}
}

func TestCleanNoMatch(t *testing.T) {
	m := ScanObservation(Observation{Host: "benign", Port: 443})
	if len(m) != 0 {
		t.Fatalf("expected no match, got %#v", m)
	}
}

func TestWeakSignalsBelowThreshold(t *testing.T) {
	// port(6)+uri(16)=22 < 35
	m := ScanObservation(Observation{Port: 50050, URIs: []string{"/submit.php"}})
	if len(m) != 0 {
		t.Fatalf("weak signals should not trip, got %#v", m)
	}
}

func TestJA3PlusPortPlusURI(t *testing.T) {
	m := ScanObservation(Observation{
		JA3: "a0e9f5d64349fb13191bc781f81f42e1", Port: 50050,
		URIs: []string{"/submit.php"},
	})
	if len(m) == 0 || m[0].Confidence < Threshold {
		t.Fatalf("expected match >= threshold, got %#v", m)
	}
}
