// Go port of the c2detect CORE check — single binary, zero deps.
// Scores TLS/network observations against a bundled C2-framework signature DB
// (JARM / JA3 / port / URI). Passive only; no network.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Signature struct {
	Family   string
	Severity string
	JARM     []string
	JA3      []string
	Ports    []int
	URIs     []string
}

// Observation is one host/connection's observed indicators.
type Observation struct {
	Host string   `json:"host"`
	IP   string   `json:"ip"`
	JARM string   `json:"jarm"`
	JA3  string   `json:"ja3"`
	Port int      `json:"port"`
	URIs []string `json:"uris"`
}

type Match struct {
	Family     string   `json:"family"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Indicators []string `json:"indicators"`
}

const Threshold = 35

var weights = map[string]int{"jarm": 42, "ja3": 24, "uri": 16, "port": 6}

var Signatures = []Signature{
	{Family: "Cobalt Strike", Severity: "critical",
		JARM:  []string{"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"},
		JA3:   []string{"a0e9f5d64349fb13191bc781f81f42e1"},
		Ports: []int{50050}, URIs: []string{"/submit.php", "/__utm.gif"}},
	{Family: "Metasploit", Severity: "high",
		Ports: []int{4444, 8443}, URIs: []string{"/INITM", "/INITJM"}},
	{Family: "Sliver", Severity: "high",
		Ports: []int{8888, 31337}, URIs: []string{"/health", "/staticfile"}},
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func uriHit(sig Signature, uris []string) bool {
	for _, u := range uris {
		for _, s := range sig.URIs {
			if s != "" && strings.Contains(u, s) {
				return true
			}
		}
	}
	return false
}

// ScanObservation scores one observation against the signature DB.
func ScanObservation(obs Observation) []Match {
	var matches []Match
	for _, sig := range Signatures {
		conf := 0
		var hits []string
		if obs.JARM != "" && contains(sig.JARM, obs.JARM) {
			conf += weights["jarm"]
			hits = append(hits, "jarm")
		}
		if obs.JA3 != "" && contains(sig.JA3, obs.JA3) {
			conf += weights["ja3"]
			hits = append(hits, "ja3")
		}
		if uriHit(sig, obs.URIs) {
			conf += weights["uri"]
			hits = append(hits, "uri")
		}
		if obs.Port != 0 && containsInt(sig.Ports, obs.Port) {
			conf += weights["port"]
			hits = append(hits, "port")
		}
		if conf > 100 {
			conf = 100
		}
		if conf >= Threshold {
			matches = append(matches, Match{sig.Family, sig.Severity, conf, hits})
		}
	}
	return matches
}

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	b, err := os.ReadFile(target)
	results := []map[string]any{}
	matchCount := 0
	if err == nil {
		var arr []Observation
		if json.Unmarshal(b, &arr) != nil {
			var one Observation
			if json.Unmarshal(b, &one) == nil {
				arr = []Observation{one}
			}
		}
		for _, obs := range arr {
			if obs.Host == "" {
				obs.Host = obs.IP
			}
			m := ScanObservation(obs)
			if len(m) > 0 {
				results = append(results, map[string]any{"host": obs.Host, "matches": m})
				matchCount += len(m)
			}
		}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"tool": "c2detect", "results": results, "match_count": matchCount, "score": matchCount,
	}, "", "  ")
	fmt.Println(string(out))
}
