package scan

import (
	"testing"
)

type want struct {
	rule string
	sev  Severity
	line int
}

func TestWorkflow(t *testing.T) {
	cases := []struct {
		name string
		yml  string
		want []want
	}{
		{"pwn request", `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
`, []want{{RulePwnRequest, High, 6}}},
		{"pwn request via refs/pull on issue_comment", `on:
  issue_comment:
    types: [created]
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - uses: ./.github/actions/build
`, []want{{RulePwnRequest, High, 7}}},
		{"checkout without ref is safe", `on: pull_request_target
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
      - run: make
`, nil},
		{"checkout then only inert steps", `on: pull_request_target
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - uses: actions/upload-artifact@v4
`, nil},
		{"plain pull_request is not privileged", `on: [pull_request]
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - run: echo "${{ github.event.pull_request.title }}"
`, nil},
		{"gated by author_association", `on: pull_request_target
jobs:
  t:
    if: github.event.pull_request.author_association == 'MEMBER'
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - run: make
`, []want{{RulePwnRequest, Medium, 6}}},
		{"environment approval counts as gate", `on: pull_request_target
jobs:
  t:
    environment: external
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - run: make
`, []want{{RulePwnRequest, Medium, 6}}},
		{"job only runs on unprivileged event", `on: [pull_request, pull_request_target]
jobs:
  t:
    if: github.event_name == 'pull_request'
    steps:
      - run: echo "${{ github.event.pull_request.body }}"
`, nil},
		{"ref guarded by event_name", `on: [pull_request, workflow_run]
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.ref }}
      - run: make
`, nil},
		{"workflow_run restricted to push", `on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  t:
    if: github.event.workflow_run.event == 'push'
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.workflow_run.head_sha }}"}
      - run: make
`, nil},
		{"script injection in run block", `"on":
  issues:
    types: [opened]
jobs:
  triage:
    steps:
      - run: |
          echo hello
          echo "${{ github.event.issue.title }}"
          echo "${{ github.event.issue.title }}"
`, []want{{RuleInjection, High, 9}}},
		{"script injection in github-script", `on:
  pull_request_target:
jobs:
  t:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const t = "${{ github.event.pull_request.title }}"
`, []want{{RuleInjection, High, 9}}},
		{"safe use through env", `on: issue_comment
jobs:
  t:
    steps:
      - env:
          BODY: ${{ github.event.comment.body }}
        run: echo "$BODY"
`, nil},
		{"trusted contexts are fine", `on: pull_request_target
jobs:
  t:
    steps:
      - run: echo "${{ github.event.pull_request.number }} ${{ github.repository }}"
`, nil},
		{"on parsed as YAML 1.1 bool key", `true: workflow_run
jobs:
  t:
    steps:
      - run: echo ${{ github.event.workflow_run.head_branch }}
`, []want{{RuleInjection, High, 5}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Workflow("w.yml", []byte(c.yml))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(c.want), got)
			}
			for i, w := range c.want {
				g := got[i]
				if g.Rule != w.rule || g.Severity != w.sev || g.Line != w.line {
					t.Errorf("finding %d = %s/%s line %d, want %s/%s line %d", i, g.Rule, g.Severity, g.Line, w.rule, w.sev, w.line)
				}
			}
		})
	}
}

func TestInvalidYAML(t *testing.T) {
	if _, err := Workflow("bad.yml", []byte("on: [\n")); err == nil {
		t.Fatal("want error")
	}
	if f, err := Workflow("empty.yml", nil); err != nil || f != nil {
		t.Fatalf("empty: %v %v", f, err)
	}
}
