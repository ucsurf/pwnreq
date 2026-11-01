// Command pwnreq finds exploitable "pwn request" and script-injection bugs in
// GitHub Actions workflows, locally or across a whole GitHub org.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ucsurf/pwnreq/internal/remote"
	"github.com/ucsurf/pwnreq/internal/scan"
)

var version = "dev"

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, nil)) }

func run(args []string, stdout, stderr io.Writer, rc *remote.Client) int {
	f := flag.NewFlagSet("pwnreq", flag.ContinueOnError)
	f.SetOutput(stderr)
	format := f.String("format", "text", "output format: text, json or sarif")
	minSev := f.String("min-severity", "medium", "lowest severity to report: medium or high")
	forks := f.Bool("forks", false, "include forked repos when scanning an org/user")
	timeout := f.Duration("timeout", 5*time.Minute, "overall timeout for remote scans")
	showVersion := f.Bool("version", false, "print version")
	f.Usage = func() {
		fmt.Fprintf(stderr, `Usage: pwnreq [flags] [target ...]

Targets (default: current directory):
  path/              a local repo or directory (scans .github/workflows/)
  file.yml           a single workflow file
  owner/repo         a GitHub repo, fetched via the API (no clone)
  org:NAME           every non-archived repo of an org or user

Flags:
`)
		f.PrintDefaults()
		fmt.Fprintf(stderr, "\nEnv: GITHUB_TOKEN or GH_TOKEN (needed for org scans because of rate limits)\nExit: 0 clean, 1 findings, 2 error\n")
	}
	if err := f.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "pwnreq", buildVersion())
		return 0
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return 2
	}
	if *minSev != "medium" && *minSev != "high" {
		fmt.Fprintf(stderr, "unknown severity %q\n", *minSev)
		return 2
	}
	targets := f.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}
	if rc == nil {
		tok := os.Getenv("GITHUB_TOKEN")
		if tok == "" {
			tok = os.Getenv("GH_TOKEN")
		}
		rc = remote.New(tok)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var findings []scan.Finding
	files, failed := 0, false
	add := func(name string, data []byte) {
		files++
		fs, err := scan.Workflow(name, data)
		if err != nil {
			fmt.Fprintln(stderr, "warning:", err)
			return
		}
		for _, x := range fs {
			if *minSev == "high" && x.Severity != scan.High {
				continue
			}
			findings = append(findings, x)
		}
	}
	scanFetched := func(wfs []remote.File) {
		for _, w := range wfs {
			add(w.Path, w.Data)
		}
	}
	var direct []string
	for _, t := range targets {
		switch {
		case strings.HasPrefix(t, "org:"):
			repos, err := rc.Repos(ctx, strings.TrimPrefix(t, "org:"), *forks)
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				failed = true
				continue
			}
			scanRepos(ctx, rc, repos, scanFetched, stderr, &failed)
		case isLocal(t):
			if err := scanLocal(t, add); err != nil {
				fmt.Fprintln(stderr, "error:", err)
				failed = true
			}
		case strings.Count(t, "/") == 1:
			direct = append(direct, t)
		default:
			fmt.Fprintf(stderr, "error: %s: no such file and not owner/repo\n", t)
			failed = true
		}
	}

	scanRepos(ctx, rc, direct, scanFetched, stderr, &failed)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	switch *format {
	case "json":
		if findings == nil {
			findings = []scan.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(findings)
	case "sarif":
		_ = writeSARIF(stdout, findings, buildVersion())
	default:
		for _, x := range findings {
			fmt.Fprintf(stdout, "%s:%d: %s [%s] job=%s on=%s\n    %s\n", x.File, x.Line, x.Rule, x.Severity, x.Job, x.Trigger, x.Message)
			if x.Evidence != "" {
				fmt.Fprintf(stdout, "    > %s\n", x.Evidence)
			}
		}
		fmt.Fprintf(stdout, "%d workflow(s) scanned, %d finding(s)\n", files, len(findings))
	}
	if failed {
		return 2
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}

func isLocal(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isWorkflow(p string) bool {
	return strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")
}

func scanLocal(p string, add func(string, []byte)) error {
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		add(filepath.ToSlash(p), b)
		return nil
	}
	// Scan workflow files directly inside p, plus any .github/workflows/
	// directory below it (monorepos, checkouts of several repos).
	return filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); path != p && (n == "node_modules" || n == "vendor" || (strings.HasPrefix(n, ".") && n != ".github")) {
				return filepath.SkipDir
			}
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		if !isWorkflow(path) || !(filepath.Dir(path) == filepath.Clean(p) || strings.HasSuffix(dir, ".github/workflows")) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		add(filepath.ToSlash(path), b)
		return nil
	})
}

// scanRepos fetches workflows of several repos concurrently and hands them
// to add sequentially.
func scanRepos(ctx context.Context, rc *remote.Client, repos []string, add func([]remote.File), stderr io.Writer, failed *bool) {
	type res struct {
		files []remote.File
		err   error
	}
	out := make([]res, len(repos))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, r := range repos {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].files, out[i].err = rc.Workflows(ctx, r)
		}()
	}
	wg.Wait()
	for _, o := range out {
		if o.err != nil {
			fmt.Fprintln(stderr, "error:", o.err)
			*failed = true
			continue
		}
		add(o.files)
	}
}
