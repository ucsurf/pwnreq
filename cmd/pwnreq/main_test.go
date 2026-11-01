package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ucsurf/pwnreq/internal/remote"
)

const wantText = `../../testdata/repo/.github/workflows/pr.yml:7: PWN001 [high] job=test on=pull_request_target
    privileged workflow checks out untrusted PR code and then runs more steps (pwn request)
    > ref: ${{ github.event.pull_request.head.sha }}
../../testdata/repo/.github/workflows/pr.yml:11: PWN002 [high] job=test on=pull_request_target
    attacker-controlled value interpolated into a script (script injection); pass it via env: instead
    > ${{ github.event.pull_request.title }}
2 workflow(s) scanned, 2 finding(s)
`

func TestLocalText(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"../../testdata/repo"}, &out, &errb, remote.New(""))
	if code != 1 {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	if out.String() != wantText {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), wantText)
	}
}

func TestFormats(t *testing.T) {
	for _, f := range []string{"json", "sarif"} {
		var out, errb bytes.Buffer
		if code := run([]string{"-format", f, "../../testdata/repo"}, &out, &errb, remote.New("")); code != 1 {
			t.Fatalf("%s: exit %d %s", f, code, errb.String())
		}
		var v any
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatalf("%s: invalid json: %v", f, err)
		}
	}
	var out bytes.Buffer
	if code := run([]string{"-min-severity", "high", "../../testdata/repo/.github/workflows/ok.yml"}, &out, &out, remote.New("")); code != 0 {
		t.Fatalf("clean file exit %d: %s", code, out.String())
	}
	if code := run([]string{"-format", "xml"}, &out, &out, remote.New("")); code != 2 {
		t.Fatalf("bad format exit %d", code)
	}
}

func TestRemoteOrg(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			w.WriteHeader(404)
		case "/users/acme/repos":
			w.Write([]byte(`[{"full_name":"acme/a"},{"full_name":"acme/old","archived":true},{"full_name":"acme/fork","fork":true}]`))
		case "/repos/acme/a/contents/.github/workflows":
			w.Write([]byte(`[{"name":"x.yml","path":".github/workflows/x.yml","type":"file","download_url":"` + srv.URL + `/raw/x.yml"}]`))
		case "/raw/x.yml":
			w.Write([]byte("on: issues\njobs:\n  t:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	rc := remote.New("")
	rc.Base = srv.URL
	var out, errb bytes.Buffer
	if code := run([]string{"org:acme"}, &out, &errb, rc); code != 1 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "acme/a/.github/workflows/x.yml:5: PWN002") {
		t.Errorf("unexpected output %s", out.String())
	}
}
