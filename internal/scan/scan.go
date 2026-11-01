// Package scan finds exploitable "pwn request" and script-injection patterns
// in GitHub Actions workflow files.
package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity of a finding.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
)

// Finding is one problem in one workflow.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Job      string   `json:"job"`
	Trigger  string   `json:"trigger"`
	Message  string   `json:"message"`
	Evidence string   `json:"evidence,omitempty"`
}

// Rule IDs.
const (
	RulePwnRequest = "PWN001"
	RuleInjection  = "PWN002"
)

// privileged triggers run with a write token / secrets while being
// triggerable by people without write access.
var privileged = map[string]bool{
	"pull_request_target":         true,
	"workflow_run":                true,
	"issue_comment":               true,
	"issues":                      true,
	"discussion":                  true,
	"discussion_comment":          true,
	"pull_request_review":         false, // fork reviews get a read-only token
	"pull_request_review_comment": false,
}

// checkoutTriggers are triggers where checking out attacker code is a pwn request.
var checkoutTriggers = map[string]bool{"pull_request_target": true, "workflow_run": true, "issue_comment": true}

var (
	exprRe = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)
	// attacker-controlled contexts (title, body, branch names, commit messages...).
	untrustedRe = regexp.MustCompile(`github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^ ]*\.page_name|commits\.[^ ]*\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name)|committer\.(?:email|name))|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))|display_title|pull_requests\.[^ ]*\.head\.ref))|head_ref)\b`)
	// refs that point at untrusted (PR head) code.
	untrustedRefRe = regexp.MustCompile(`github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch)|refs/pull/|github\.event\.pull_request\.merge_commit_sha|github\.event\.issue\.pull_request|steps\.[^ ]*\.outputs\.(?:head|sha|ref)`)
	// conditions that restrict who can trigger the job.
	eventEqRe = regexp.MustCompile(`github\.event_name\s*==\s*'([a-z_]+)'`)
	// workflow_run gated to push-triggered upstream runs (trusted code).
	wrPushRe = regexp.MustCompile(`workflow_run\.event\s*==\s*'(?:push|schedule|release|workflow_dispatch)'|workflow_run\.event\s*!=\s*'pull_request'`)
	// steps that don't execute code from the checked-out tree.
	inertUses = regexp.MustCompile(`^(?i)(actions/(upload-artifact|download-artifact|cache/save|labeler|stale|first-interaction)|peter-evans/(create-or-update-comment|find-comment)|marocchino/sticky-pull-request-comment|thollander/actions-comment-pull-request|mshick/add-pr-comment)@`)
	gateRe    = regexp.MustCompile(`author_association|github\.actor\s*==|head\.repo\.full_name\s*==\s*github\.repository|head\.repo\.fork\s*==\s*false|!github\.event\.pull_request\.head\.repo\.fork|contains\(github\.event\.pull_request\.labels|github\.event\.label\.name|github\.event\.workflow_run\.head_repository\.full_name\s*==|github\.repository_owner\s*==\s*github\.actor`)
)

// Workflow scans one workflow file's bytes. name is used for reporting.
func Workflow(name string, data []byte) ([]Finding, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	doc := root.Content[0]
	triggers := triggerNames(get(doc, "on"))
	var priv []string
	for _, t := range triggers {
		if privileged[t] {
			priv = append(priv, t)
		}
	}
	if len(priv) == 0 {
		return nil, nil
	}
	jobs := get(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}
	var out []Finding
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		jobIf := str(get(job, "if"))
		if onlyUnprivEvents(jobIf, priv) || wrPushRe.MatchString(jobIf) {
			continue
		}
		// a deployment environment can require manual approval.
		gated := gateRe.MatchString(jobIf) || get(job, "environment") != nil
		steps := get(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		checkedOut := -1
		for si, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			stepIf := str(get(step, "if"))
			if onlyUnprivEvents(stepIf, priv) || wrPushRe.MatchString(stepIf) {
				continue
			}
			stepGated := gated || gateRe.MatchString(stepIf)
			uses := str(get(step, "uses"))
			// PWN001: checkout of untrusted ref, followed by any further step.
			if strings.HasPrefix(strings.ToLower(uses), "actions/checkout@") && checkedOut < 0 {
				ref := str(get(get(step, "with"), "ref")) + " " + str(get(get(step, "with"), "repository"))
				if untrustedRefRe.MatchString(ref) && !onlyUnprivEvents(ref, priv) && anyTrigger(priv, checkoutTriggers) != "" && executesLater(steps.Content[si+1:]) {
					checkedOut = si
					sev := High
					if stepGated {
						sev = Medium
					}
					out = append(out, Finding{Rule: RulePwnRequest, Severity: sev, File: name, Line: step.Line, Job: jobName,
						Trigger:  anyTrigger(priv, checkoutTriggers),
						Message:  "privileged workflow checks out untrusted PR code and then runs more steps (pwn request)" + gatedNote(stepGated),
						Evidence: "ref: " + strings.TrimSpace(str(get(get(step, "with"), "ref")))})
				}
			}
			// PWN002: untrusted expression inside run: or github-script.
			seen := map[string]bool{}
			for _, sn := range scriptNodes(step) {
				for _, m := range exprRe.FindAllStringSubmatch(sn.Value, -1) {
					if !untrustedRe.MatchString(m[1]) || seen[m[0]] || onlyUnprivEvents(m[1], priv) {
						continue
					}
					seen[m[0]] = true
					sev := High
					if stepGated {
						sev = Medium
					}
					out = append(out, Finding{Rule: RuleInjection, Severity: sev, File: name, Line: lineOf(sn, m[0]), Job: jobName,
						Trigger:  strings.Join(priv, ","),
						Message:  "attacker-controlled value interpolated into a script (script injection); pass it via env: instead" + gatedNote(stepGated),
						Evidence: strings.TrimSpace(m[0])})
				}
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Line < out[b].Line })
	return out, nil
}

// onlyUnprivEvents reports whether expr restricts itself to event names
// (github.event_name == 'x') none of which is a privileged trigger in use.
func onlyUnprivEvents(expr string, priv []string) bool {
	ms := eventEqRe.FindAllStringSubmatch(expr, -1)
	if len(ms) == 0 || strings.Contains(expr, "!=") {
		return false
	}
	for _, m := range ms {
		for _, p := range priv {
			if m[1] == p {
				return false
			}
		}
	}
	return true
}

// executesLater reports whether any of the remaining steps may run code
// from the checked-out tree.
func executesLater(steps []*yaml.Node) bool {
	for _, st := range steps {
		if get(st, "run") != nil {
			return true
		}
		if u := str(get(st, "uses")); u != "" && !inertUses.MatchString(u) && !strings.HasPrefix(strings.ToLower(u), "actions/checkout@") {
			return true
		}
	}
	return false
}

func gatedNote(g bool) string {
	if g {
		return " [job/step has an actor/label gate; verify it]"
	}
	return ""
}

func anyTrigger(ts []string, set map[string]bool) string {
	for _, t := range ts {
		if set[t] {
			return t
		}
	}
	return ""
}

func scriptNodes(step *yaml.Node) []*yaml.Node {
	var n []*yaml.Node
	if r := get(step, "run"); r != nil && r.Kind == yaml.ScalarNode {
		n = append(n, r)
	}
	if strings.HasPrefix(strings.ToLower(str(get(step, "uses"))), "actions/github-script@") {
		if s := get(get(step, "with"), "script"); s != nil && s.Kind == yaml.ScalarNode {
			n = append(n, s)
		}
	}
	return n
}

// lineOf estimates the source line of sub inside a scalar node.
func lineOf(n *yaml.Node, sub string) int {
	i := strings.Index(n.Value, sub)
	if i < 0 {
		return n.Line
	}
	off := strings.Count(n.Value[:i], "\n")
	if n.Style == yaml.LiteralStyle || n.Style == yaml.FoldedStyle {
		return n.Line + 1 + off
	}
	return n.Line + off
}

func triggerNames(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var s []string
		for _, c := range n.Content {
			s = append(s, c.Value)
		}
		return s
	case yaml.MappingNode:
		var s []string
		for i := 0; i < len(n.Content); i += 2 {
			s = append(s, n.Content[i].Value)
		}
		return s
	}
	return nil
}

// get returns the value for key in a mapping node. "on" also matches the
// YAML 1.1 boolean spelling "true".
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; k == key || (key == "on" && k == "true") {
			return n.Content[i+1]
		}
	}
	return nil
}

func str(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
