package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzWorkflow(f *testing.F) {
	files, _ := filepath.Glob("../../testdata/repo/.github/workflows/*.y*ml")
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	for _, s := range []string{"", "on: pull_request_target", "on: [push, pull_request_target]\njobs: {a: {steps: [{run: '${{ github.event.pull_request.title }}'}]}}", "jobs: []", "on: {pull_request_target: null}\njobs: {x: null}", "&a [*a]", "on: !!binary aGk="} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fs, err := Workflow("w.yml", data)
		if err != nil {
			return
		}
		for _, x := range fs {
			if x.Line < 0 {
				t.Fatalf("negative line in %+v", x)
			}
		}
	})
}

func TestWorkflowEdgeCases(t *testing.T) {
	for _, s := range []string{"", "---\n", "&a [*a]", "on: pull_request_target\njobs: null", "on: pull_request_target\njobs: {a: {steps: null}}", "on: pull_request_target\njobs: {a: {steps: [null, 1, {run: null}]}}", "[1,2]"} {
		if _, err := Workflow("w.yml", []byte(s)); err != nil {
			t.Logf("%q: %v", s, err)
		}
	}
	fs, err := Workflow("w.yml", []byte("true: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: '${{ github.event.pull_request.head.sha }}'}\n      - run: make\n"))
	if err != nil || len(fs) == 0 {
		t.Fatalf("YAML 1.1 'true' key for on: not detected: %v %v", fs, err)
	}
}
