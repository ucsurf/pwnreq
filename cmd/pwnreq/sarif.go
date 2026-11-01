package main

import (
	"encoding/json"
	"io"

	"github.com/ucsurf/pwnreq/internal/scan"
)

var ruleDesc = map[string]string{
	scan.RulePwnRequest: "Privileged workflow checks out and runs untrusted pull request code",
	scan.RuleInjection:  "Attacker-controlled expression interpolated into a script",
}

func writeSARIF(w io.Writer, fs []scan.Finding, ver string) error {
	type m map[string]any
	rules := []m{}
	for _, id := range []string{scan.RulePwnRequest, scan.RuleInjection} {
		rules = append(rules, m{"id": id, "shortDescription": m{"text": ruleDesc[id]},
			"helpUri": "https://github.com/ucsurf/pwnreq#rules"})
	}
	results := []m{}
	for _, f := range fs {
		level := "error"
		if f.Severity == scan.Medium {
			level = "warning"
		}
		results = append(results, m{"ruleId": f.Rule, "level": level, "message": m{"text": f.Message},
			"locations": []m{{"physicalLocation": m{"artifactLocation": m{"uri": f.File}, "region": m{"startLine": f.Line}}}}})
	}
	doc := m{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []m{{"tool": m{"driver": m{"name": "pwnreq", "version": ver, "informationUri": "https://github.com/ucsurf/pwnreq", "rules": rules}}, "results": results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
