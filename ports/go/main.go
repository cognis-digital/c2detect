// Go port of the Cognis scan logic — single binary, zero deps.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Finding struct {
	ID    string `json:"id"`
	Sev   string `json:"sev"`
	Where string `json:"where"`
}

var rules = [][3]string{{"GEN-001", "high", "TODO"}, {"GEN-002", "medium", "FIXME"}, {"GEN-003", "low", "XXX"}}

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	var fs []Finding
	filepath.Walk(target, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, r := range rules {
			if strings.Contains(string(b), r[2]) {
				fs = append(fs, Finding{r[0], r[1], p})
			}
		}
		return nil
	})
	out, _ := json.MarshalIndent(map[string]any{"tool": "c2detect", "findings": fs, "score": len(fs)}, "", "  ")
	fmt.Println(string(out))
}
