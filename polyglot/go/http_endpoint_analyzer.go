package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// C2Signature holds the known signatures for each C2 framework
type C2Signature struct {
	Name        string
	Paths       []string
	Headers     map[string]string
	Patterns    []string
	VersionKeys []string
	Timeout     time.Duration
}

var c2Signatures = []C2Signature{
	// Cobalt Strike
	{
		Name:   "Cobalt Strike",
		Paths:  []string{"beacon", "beacon/", "c2/", "/beacon"},
		Headers: map[string]string{
			"X-Beacon-Version": "4.0",
		},
		Patterns: []string{
			`"version":"4\.0`,
			`"type":"beacon",`,
		},
		VersionKeys: []string{"X-Beacon-Version"},
		Timeout:     2 * time.Second,
	},

	// Sliver
	{
		Name:   "Sliver",
		Paths:  []string{"api/v1/auth/login", "api/v1/session", "/api/v1/auth/login"},
		Headers: map[string]string{
			"X-Sliver-Version": "0.12.0",
		},
		Patterns: []string{
			`"version":"0\.12`,
			`"type":"sliver",`,
		},
		VersionKeys: []string{"X-Sliver-Version"},
		Timeout:     3 * time.Second,
	},

	// Mythic
	{
		Name:   "Mythic",
		Paths:  []string{"mythic/", "api/mythic/", "/mythic/"},
		Headers: map[string]string{
			"X-Mythic-Version": "2.0.0",
		},
		Patterns: []string{
			`"version":"2\.0`,
			`"type":"mythic",`,
		},
		VersionKeys: []string{"X-Mythic-Version"},
		Timeout:     3 * time.Second,
	},

	// Havoc
	{
		Name:   "Havoc",
		Paths:  []string{"api/v1/auth/login", "api/v1/session", "/api/v1/auth/login"},
		Headers: map[string]string{
			"X-Havoc-Version": "0.8.0",
		},
		Patterns: []string{
			`"version":"0\.8`,
			`"type":"havoc",`,
		},
		VersionKeys: []string{"X-Havoc-Version"},
		Timeout:     3 * time.Second,
	},

	// Brute Ratel
	{
		Name:   "Brute Ratel",
		Paths:  []string{"ratel/", "api/ratel/", "/ratel/"},
		Headers: map[string]string{
			"X-Ratel-Version": "1.0.0",
		},
		Patterns: []string{
			`"version":"1\.0`,
			`"type":"ratel",`,
		},
		VersionKeys: []string{"X-Ratel-Version"},
		Timeout:     2 * time.Second,
	},

	// Generic fallback - common C2 patterns
	{
		Name:   "Generic C2",
		Paths:  []string{"/api/v1/", "/api/management/"},
		Patterns: []string{
			`"type":"beacon|sliver|mythic|havoc|ratel",`,
			`"protocol":"http|https",`,
		},
		VersionKeys: []string{},
		Timeout:     5 * time.Second,
	},
}

// DetectionResult holds the result of analyzing a single C2 signature
type DetectionResult struct {
	Name        string
	Confidence   float64
	MatchType    string // path, header, pattern, or generic
	Matches      []string
	VersionFound string
	TimeoutHit   bool
}

// AnalysisResult holds the complete analysis of a target URL
type AnalysisResult struct {
	URL         string
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	Signatures  []DetectionResult
	TopMatch    *DetectionResult
	HTTPInfo    HTTPInfo
}

// HTTPInfo holds the raw HTTP response information
type HTTPInfo struct {
	Status       int
	Headers      map[string][]string
	Body         string
	ContentType  string
	ContentLength int64
	TimeoutHit   bool
}

// HTTPAnalyzer handles the HTTP analysis for C2 detection
type HTTPAnalyzer struct {
	client *http.Client
}

func NewHTTPAnalyzer() *HTTPAnalyzer {
	return &HTTPAnalyzer{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (a *HTTPAnalyzer) Analyze(targetURL string) (*AnalysisResult, error) {
	startTime := time.Now()
	
	result := &AnalysisResult{
		URL:      targetURL,
		StartTime: startTime,
		HTTPInfo: HTTPInfo{},
	}

	// Parse the URL and try multiple paths
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result, fmt.Errorf("failed to parse URL: %w", err)
	}

	host := parsedURL.Host
	path := parsedURL.Path

	// Try the base path first
	result.HTTPInfo = a.fetchResponse(host, path)
	
	// If no response or empty body, try common C2 paths
	if result.HTTPInfo.Status == 0 || result.HTTPInfo.Body == "" {
		commonPaths := []string{"/beacon", "/api/v1/auth/login", "/mythic/", "/ratel/"}
		
		for _, cp := range commonPaths {
			result.HTTPInfo = a.fetchResponse(host, cp)
			if result.HTTPInfo.Status != 0 && len(result.HTTPInfo.Body) > 0 {
				break
			}
		}
	}

	// Analyze the response against all signatures
	for _, sig := range c2Signatures {
		result.Signatures = append(result.Signatures, a.analyzeSignature(sig, result.HTTPInfo))
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	// Find the top match
	if len(result.Signatures) > 0 {
		sort.Slice(result.Signatures, func(i, j int) bool {
			return result.Signatures[i].Confidence > result.Signatures[j].Confidence
		})
		result.TopMatch = &result.Signatures[0]
	}

	return result, nil
}

func (a *HTTPAnalyzer) fetchResponse(host, path string) HTTPInfo {
	var resp HTTPInfo
	
	reqURL := fmt.Sprintf("http://%s%s", host, path)
	if strings.HasPrefix(path, "/") && !strings.Contains(reqURL, "://") {
		reqURL = reqURL[7:] + path // remove leading / if present
	}

	resp.Status = 0
	resp.TimeoutHit = false
	
	var body []byte
	var err error
	
	// Try HTTP first, then HTTPS
	for _, scheme := range []string{"http", "https"} {
		urlToTry := fmt.Sprintf("%s://%s%s", scheme, host, path)
		
		req, err := http.NewRequest("GET", urlToTry, nil)
		if err != nil {
			continue
		}

		resp, err = a.client.Do(req)
		if err == nil && resp != nil {
			body, err = io.ReadAll(resp.Body)
			if err == nil {
				resp.Status = resp.StatusCode
				resp.Headers = make(map[string][]string)
				for k, v := range resp.Header {
					resp.Headers[k] = append(resp.Headers[k], v...)
				}
				resp.ContentType = strings.Split(resp.Header.Get("Content-Type"), ";")[0]
				resp.ContentLength = int64(len(body))
				resp.Body = string(body)
				resp.TimeoutHit = resp.StatusCode >= 500 || err != nil
				
				if resp.Status > 0 {
					return resp
				}
			}
		}
		
		if resp.Status > 0 {
			break
		}
	}

	return resp
}

func (a *HTTPAnalyzer) analyzeSignature(sig C2Signature, httpInfo HTTPInfo) DetectionResult {
	result := DetectionResult{
		Name:        sig.Name,
		Confidence:   0.0,
		TimeoutHit:   httpInfo.TimeoutHit,
	}

	if httpInfo.Status == 0 || len(httpInfo.Body) == 0 {
		return result
	}

	// Check paths
	for _, p := range sig.Paths {
		if strings.Contains(httpInfo.Body, p) || 
		   strings.Contains(httpInfo.URL, p) {
			result.Confidence = max(result.Confidence, 0.6)
			result.MatchType = "path"
			result.Matches = append(result.Matches, fmt.Sprintf("path match: %s", p))
		}
	}

	// Check headers
	for k, v := range sig.Headers {
		if strings.Contains(httpInfo.Body, k) || 
		   httpInfo.Headers[k] != "" {
			result.Confidence = max(result.Confidence, 0.7)
			result.MatchType = "header"
			result.Matches = append(result.Matches, fmt.Sprintf("header match: %s", k))
		}
	}

	// Check patterns in body
	for _, pattern := range sig.Patterns {
		if strings.Contains(httpInfo.Body, pattern) {
			result.Confidence = max(result.Confidence, 0.8)
			result.MatchType = "pattern"
			result.Matches = append(result.Matches, fmt.Sprintf("pattern match: %s", pattern))
		}
	}

	// Check version keys in headers
	for _, key := range sig.VersionKeys {
		if httpInfo.Headers[key] != "" {
			result.Confidence = max(result.Confidence, 0.85)
			result.MatchType = "version"
			result.Matches = append(result.Matches, fmt.Sprintf("version header: %s=%s", key, httpInfo.Headers[key]))
		}
	}

	return result
}

func (a *HTTPAnalyzer) GetTopMatch(result *AnalysisResult) string {
	if result.TopMatch == nil || result.TopMatch.Confidence == 0 {
		return "Unknown"
	}
	
	name := result.TopMatch.Name
	
	// Add version if found
	if result.TopMatch.VersionFound != "" {
		name += fmt.Sprintf(" v%s", result.TopMatch.VersionFound)
	}

	return name
}

func (a *HTTPAnalyzer) PrintResult(result *AnalysisResult) {
	fmt.Printf("\n=== C2 Detection Analysis ===\n")
	fmt.Printf("Target: %s\n", result.URL)
	fmt.Printf("Duration: %.3fs\n", result.Duration.Seconds())
	fmt.Printf("Status: %d\n", result.HTTPInfo.Status)
	
	if len(result.Signatures) > 0 {
		fmt.Printf("\n--- Detected Signatures (sorted by confidence) ---\n")
		
		for i, sig := range result.Signatures {
			confidenceStr := fmt.Sprintf("%.1f%%", sig.Confidence*100)
			if sig.TimeoutHit {
				confidenceStr += " [timeout]"
			}
			
			fmt.Printf("\n%d. %s\n", i+1, sig.Name)
			fmt.Printf("   Confidence: %s\n", confidenceStr)
			fmt.Printf("   Type: %s\n", sig.MatchType)
			
			if len(sig.Matches) > 0 {
				for _, m := range sig.Matches {
					fmt.Printf("   - %s\n", m)
				}
			}
		}
		
		if result.TopMatch != nil && result.TopMatch.Confidence > 0.5 {
			fmt.Printf("\n--- TOP MATCH ---\n")
			fmt.Printf("%s (Confidence: %.1f%%)\n", 
				result.GetTopMatch(result), 
				result.TopMatch.Confidence*100)
		}
	} else {
		fmt.Println("No signatures detected.")
		
		if result.HTTPInfo.Status == 200 && len(result.HTTPInfo.Body) > 0 {
			fmt.Printf("\n--- Raw Response (first 500 chars) ---\n")
			fmt.Println(result.HTTPInfo.Body[:min(500, len(result.HTTPInfo.Body))])
		} else if result.HTTPInfo.Status != 0 {
			fmt.Printf("Status: %d\n", result.HTTPInfo.Status)
		}
	}
	
	if result.HTTPInfo.ContentType != "" {
		fmt.Printf("\n--- Content-Type ---\n")
		fmt.Println(result.HTTPInfo.ContentType)
	}
}

func main() {
	analyzer := NewHTTPAnalyzer()
	
	// Default target - can be overridden via command line
	targetURL := "http://localhost:8080/beacon"
	if len(os.Args) > 1 {
		targetURL = os.Args[1]
	}

	fmt.Printf("C2 Endpoint Analyzer v1.0\n")
	fmt.Printf("Analyzing: %s\n", targetURL)
	
	result, err := analyzer.Analyze(targetURL)
	if err != nil {
		fmt.Printf("Error during analysis: %v\n", err)
		os.Exit(1)
	}

	analyzer.PrintResult(result)
	
	// Exit with appropriate code based on detection
	if result.TopMatch != nil && result.TopMatch.Confidence > 0.5 {
		fmt.Printf("\nFinal verdict: %s detected!\n", analyzer.GetTopMatch(result))
		os.Exit(0)
	} else if len(result.Signatures) > 0 {
		fmt.Println("Partial matches found - verify manually.")
		os.Exit(1)
	} else {
		fmt.Println("No clear C2 signature detected.")
		os.Exit(2)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}