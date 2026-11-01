# pwnreq

[![CI](https://github.com/ucsurf/pwnreq/actions/workflows/ci.yml/badge.svg)](https://github.com/ucsurf/pwnreq/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ucsurf/pwnreq.svg)](https://pkg.go.dev/github.com/ucsurf/pwnreq)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Find exploitable "pwn requests" and script injection in GitHub Actions — in one repo or across a whole org, without cloning anything.**

`pwnreq` does one thing: it reports workflows where **someone without write access can run code with your secrets**. No config, no noise from style or hardening rules. Every finding is something an outsider could trigger.

![demo](docs/demo.gif)

```sh
go install github.com/ucsurf/pwnreq/cmd/pwnreq@latest
```

Or grab a binary from the [releases](https://github.com/ucsurf/pwnreq/releases).

## Example

```console
$ pwnreq                       # scans ./.github/workflows
.github/workflows/pr.yml:7: PWN001 [high] job=test on=pull_request_target
    privileged workflow checks out untrusted PR code and then runs more steps (pwn request)
    > ref: ${{ github.event.pull_request.head.sha }}
.github/workflows/pr.yml:11: PWN002 [high] job=test on=pull_request_target
    attacker-controlled value interpolated into a script (script injection); pass it via env: instead
    > ${{ github.event.pull_request.title }}
2 workflow(s) scanned, 2 finding(s)
```

Scan remote repos and entire orgs straight from the GitHub API (archived repos and forks are skipped):

```sh
export GITHUB_TOKEN=$(gh auth token)   # optional for a few repos, needed for orgs
pwnreq owner/repo
pwnreq org:my-company                  # works for user accounts too
pwnreq -format json org:my-company | jq '.[] | select(.severity=="high")'
```

Exit codes: `0` clean, `1` findings, `2` error — so it drops straight into CI.

## Rules

| ID | Severity | What it catches |
|---|---|---|
| `PWN001` | high | A `pull_request_target`, `workflow_run` or `issue_comment` workflow checks out the PR head (`head.sha`, `head.ref`, `refs/pull/N/...`, `workflow_run.head_sha`, ...) and then runs another step that can execute that code (`run:`, local actions, build actions). |
| `PWN002` | high | An attacker-controlled expression (PR/issue title or body, comment body, branch name, commit message, ...) is interpolated with `${{ }}` into `run:` or `actions/github-script` in a workflow triggered by `pull_request_target`, `workflow_run`, `issue_comment`, `issues` or `discussion*`. |

Findings drop to **medium** when the job or step is gated (`author_association`, actor or label checks, same-repo checks, or a deployment `environment:` that can require approval). They are skipped entirely when the job, step or ref is limited to an unprivileged event (`github.event_name == 'pull_request'`) or a `workflow_run` is limited to `push` upstream runs. Use `-min-severity high` to see only ungated findings.

### Fixing them

- **PWN001:** split the workflow: build untrusted code under `pull_request` (no secrets), then post results from a separate `workflow_run` job that only reads artifacts. If you must check out PR code in a privileged job, gate it behind a label or an environment with required reviewers.
- **PWN002:** move the value into `env:` and reference it as a shell variable:

  ```yaml
  - env:
      TITLE: ${{ github.event.pull_request.title }}
    run: echo "$TITLE"
  ```

## How is this different from zizmor or actionlint?

[zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) are excellent, broad tools — use them. `pwnreq` is deliberately narrow:

- **Only exploitable-by-outsiders findings.** No pinning, permissions or style warnings, so the output of an org-wide scan is a short list you can act on today.
- **Org-wide remote scans in one command** (`org:NAME`) — no clone, no config, no Python/Rust toolchain. Workflow files are fetched from `raw.githubusercontent.com`, so a scan costs ~1 API call per repo.
- **Single static binary**, SARIF/JSON output, a GitHub Action and a pre-commit hook.

## GitHub Action

```yaml
name: pwnreq
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  pwnreq:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: ucsurf/pwnreq@v0.1.1
        with:
          sarif: pwnreq.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pwnreq.sarif
```

Inputs: `path` (default `.`), `min-severity` (`medium`/`high`), `sarif` (path for a SARIF report), `version` (release to use; defaults to the tag you pinned).

The action downloads the prebuilt release binary for the runner (Linux, macOS, Windows; x64 and arm64) and verifies it against `checksums.txt`, so it adds about a second to your job and needs no Go toolchain. Pinned to a branch or commit SHA instead of a tag, it sets up Go and builds from source.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ucsurf/pwnreq
    rev: v0.1.1
    hooks:
      - id: pwnreq
```

## Usage

```
pwnreq [flags] [target ...]

Targets (default: current directory):
  path/              a local repo or directory (scans .github/workflows/)
  file.yml           a single workflow file
  owner/repo         a GitHub repo, fetched via the API (no clone)
  org:NAME           every non-archived repo of an org or user

  -format string        output format: text, json or sarif (default "text")
  -min-severity string  lowest severity to report: medium or high (default "medium")
  -forks                include forked repos when scanning an org/user
  -timeout duration     overall timeout for remote scans (default 5m0s)
  -version              print version
```

## Accuracy

Tuned against ~2,000 real workflows from ~350 public repos that use `pull_request_target`, `workflow_run` or `issue_comment`. False positives we found (event-name guards, push-only `workflow_run`, steps that never execute the checkout, duplicate hits) are covered by tests. It's static analysis: a finding means "an outsider can probably reach this", so confirm before reporting. If you find a false positive or a miss, please [open an issue](https://github.com/ucsurf/pwnreq/issues) with the workflow.

If you report a finding to another project, [disclose](https://github.com/ucsurf/disclose) tells you where to send it privately.

## License

MIT
