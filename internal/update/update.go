// Package update replaces the running nokey binary with the latest GitHub
// release, after checking the archive against the release's checksums.txt.
package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Repo is the GitHub repository releases are published to.
const Repo = "nokey-ai/nokey"

// maxDownload bounds every response body. Release archives are ~30 MB.
const maxDownload = 200 << 20

// Client fetches releases. BaseURL is the GitHub API root and is
// overridable so tests can point it at a local server.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}

// NewClient returns a client for api.github.com.
func NewClient() *Client {
	return &Client{HTTP: http.DefaultClient, BaseURL: "https://api.github.com"}
}

// Release is the subset of the GitHub release object nokey uses.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset is a file attached to a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Version returns the release tag without its leading "v".
func (r *Release) Version() string {
	return strings.TrimPrefix(r.TagName, "v")
}

// Latest returns the newest non-prerelease release.
func (c *Client) Latest(ctx context.Context) (*Release, error) {
	body, err := c.get(ctx, c.BaseURL+"/repos/"+Repo+"/releases/latest")
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse latest release: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("latest release has no tag")
	}
	return &rel, nil
}

// ArchiveName is the GoReleaser archive name for a version and platform.
func ArchiveName(version, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("nokey_%s_%s_%s.%s", version, goos, goarch, ext)
}

// Download fetches the archive for goos/goarch from rel, verifies it against
// checksums.txt and returns the nokey binary inside it.
func (c *Client) Download(ctx context.Context, rel *Release, goos, goarch string) ([]byte, error) {
	name := ArchiveName(rel.Version(), goos, goarch)
	archiveURL, sumsURL := "", ""
	for _, a := range rel.Assets {
		switch a.Name {
		case name:
			archiveURL = a.URL
		case "checksums.txt":
			sumsURL = a.URL
		}
	}
	if archiveURL == "" {
		return nil, fmt.Errorf("release %s has no build for %s/%s", rel.TagName, goos, goarch)
	}
	if sumsURL == "" {
		return nil, fmt.Errorf("release %s has no checksums.txt", rel.TagName)
	}

	sums, err := c.get(ctx, sumsURL)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums: %w", err)
	}
	want, err := checksumFor(sums, name)
	if err != nil {
		return nil, err
	}
	archive, err := c.get(ctx, archiveURL)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("checksum mismatch for %s", name)
	}

	if goos == "windows" {
		return extractZip(archive, "nokey.exe")
	}
	return extractTarGz(archive, "nokey")
}

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDownload {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, maxDownload)
	}
	return body, nil
}

// checksumFor finds name's SHA-256 in a sha256sum-format file.
func checksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[1] == name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

func extractTarGz(archive []byte, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == binName {
			return readBounded(tr)
		}
	}
	return nil, fmt.Errorf("archive has no %s", binName)
}

func extractZip(archive []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		defer rc.Close()
		return readBounded(rc)
	}
	return nil, fmt.Errorf("archive has no %s", binName)
}

func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}
	if len(data) > maxDownload {
		return nil, errors.New("binary in archive is too large")
	}
	return data, nil
}

// Replace writes bin over the executable at path. The new file is written
// next to it and renamed into place, so a failure leaves the old binary
// intact. Windows will not overwrite a running executable, so there the old
// one is moved aside first.
func Replace(path string, bin []byte, goos string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nokey-update-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if _, err := tmp.Write(bin); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil { //nolint:gosec // an executable must be world-executable
		return fmt.Errorf("chmod new binary: %w", err)
	}

	if goos == "windows" {
		old := path + ".old"
		_ = os.Remove(old)
		if err := os.Rename(path, old); err != nil {
			return fmt.Errorf("move old binary aside: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			_ = os.Rename(old, path)
			return fmt.Errorf("install new binary: %w", err)
		}
		return nil
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// Newer reports whether release version a is newer than b. Both must be
// plain MAJOR.MINOR.PATCH, optionally prefixed with "v".
func Newer(a, b string) (bool, error) {
	pa, err := parse(a)
	if err != nil {
		return false, err
	}
	pb, err := parse(b)
	if err != nil {
		return false, err
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i], nil
		}
	}
	return false, nil
}

// IsRelease reports whether v is a plain release version rather than a
// development build ("dev", or a git describe like v0.6.5-3-gabc1234).
func IsRelease(v string) bool {
	_, err := parse(v)
	return err == nil
}

func parse(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not a release version: %q", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("not a release version: %q", v)
		}
		out[i] = n
	}
	return out, nil
}

// HomebrewManaged reports whether the resolved executable path lives in a
// Homebrew Caskroom or Cellar, where brew must do the upgrade.
func HomebrewManaged(resolved string) bool {
	p := filepath.ToSlash(resolved)
	return strings.Contains(p, "/Caskroom/") || strings.Contains(p, "/Cellar/")
}
