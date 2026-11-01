// Package remote fetches workflow files from GitHub without cloning.
package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to the GitHub REST API.
type Client struct {
	HTTP  *http.Client
	Base  string // API base, default https://api.github.com
	Token string
}

// New returns a client with sane defaults.
func New(token string) *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Base: "https://api.github.com", Token: token}
}

// File is a fetched workflow.
type File struct {
	Path string // owner/repo/.github/workflows/x.yml
	URL  string
	Data []byte
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pwnreq")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

var errNotFound = fmt.Errorf("not found")

// Repos lists non-archived, non-fork repositories of an org or user.
func (c *Client) Repos(ctx context.Context, owner string, includeForks bool) ([]string, error) {
	var out []string
	kind := "orgs"
	for page := 1; ; page++ {
		var rs []struct {
			FullName string `json:"full_name"`
			Archived bool   `json:"archived"`
			Fork     bool   `json:"fork"`
		}
		err := c.get(ctx, fmt.Sprintf("/%s/%s/repos?per_page=100&page=%d", kind, url.PathEscape(owner), page), &rs)
		if err == errNotFound && kind == "orgs" && page == 1 {
			kind = "users"
			page = 0
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.Archived || (r.Fork && !includeForks) {
				continue
			}
			out = append(out, r.FullName)
		}
		if len(rs) < 100 {
			return out, nil
		}
	}
}

// Workflows fetches all workflow files of owner/repo at the default branch.
func (c *Client) Workflows(ctx context.Context, repo string) ([]File, error) {
	var entries []struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Type        string `json:"type"`
		HTMLURL     string `json:"html_url"`
		DownloadURL string `json:"download_url"`
	}
	if err := c.get(ctx, "/repos/"+repo+"/contents/.github/workflows", &entries); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	var out []File
	for _, e := range entries {
		if e.Type != "file" || !(strings.HasSuffix(e.Name, ".yml") || strings.HasSuffix(e.Name, ".yaml")) {
			continue
		}
		data, err := c.raw(ctx, e.DownloadURL)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", repo, e.Path, err)
		}
		out = append(out, File{Path: repo + "/" + e.Path, URL: e.HTMLURL, Data: data})
	}
	return out, nil
}

// raw downloads a file from its download_url. raw.githubusercontent.com
// is not metered by the REST API rate limit.
func (c *Client) raw(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pwnreq")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}
