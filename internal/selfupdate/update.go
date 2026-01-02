// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"
)

// UpdateOptions configures self-update behavior.
type UpdateOptions struct {
	CurrentVersion string
	InstallDir     string
	Force          bool // Allow major version jumps
	DryRun         bool
}

// UpdateResult contains the result of an update operation.
type UpdateResult struct {
	OldVersion string
	NewVersion string
	Updated    bool
	Message    string
}

// GitHubRelease represents a GitHub release API response.
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a release asset.
type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Update performs a self-update to the latest release.
func Update(opts UpdateOptions) (*UpdateResult, error) {
	result := &UpdateResult{OldVersion: opts.CurrentVersion}

	// Dev build guard
	if opts.CurrentVersion == "dev" && !opts.Force {
		result.Message = "Dev build cannot self-update without --self-update-force"
		return result, nil
	}

	// Fetch latest release
	release, err := fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}

	newVersion := strings.TrimPrefix(release.TagName, "v")
	result.NewVersion = newVersion

	// Compare versions
	if !opts.Force {
		cmp, err := compareVersions(opts.CurrentVersion, newVersion)
		if err != nil {
			return nil, fmt.Errorf("compare versions: %w", err)
		}
		if cmp >= 0 {
			result.Message = fmt.Sprintf("Already at version %s (latest: %s)", opts.CurrentVersion, newVersion)
			return result, nil
		}

		// Check for major version jump
		if isMajorJump(opts.CurrentVersion, newVersion) {
			return nil, fmt.Errorf("major version jump from %s to %s requires --self-update-force", opts.CurrentVersion, newVersion)
		}
	}

	if opts.DryRun {
		result.Message = fmt.Sprintf("Would update from %s to %s", opts.CurrentVersion, newVersion)
		return result, nil
	}

	// Find required assets
	archiveAsset := findAsset(release.Assets, assetName())
	if archiveAsset == nil {
		return nil, fmt.Errorf("archive asset not found: %s", assetName())
	}

	// Try SHA2-512SUMS first (shellsentry preference), fall back to SHA256SUMS
	checksumFile := "SHA2-512SUMS"
	checksumsAsset := findAsset(release.Assets, checksumFile)
	if checksumsAsset == nil {
		checksumFile = "SHA256SUMS"
		checksumsAsset = findAsset(release.Assets, checksumFile)
	}
	if checksumsAsset == nil {
		return nil, errors.New("no checksum file found in release (tried SHA2-512SUMS, SHA256SUMS)")
	}

	sigAsset := findAsset(release.Assets, checksumFile+".minisig")
	if sigAsset == nil {
		return nil, fmt.Errorf("%s.minisig not found in release - signature required", checksumFile)
	}

	// Download checksums and signature
	checksums, err := downloadBytes(checksumsAsset.BrowserDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}

	signature, err := downloadBytes(sigAsset.BrowserDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("download signature: %w", err)
	}

	// Verify minisign signature FIRST (before trusting checksums)
	if err := verifyMinisignSignature(checksums, signature); err != nil {
		return nil, fmt.Errorf("SECURITY: signature verification failed: %w", err)
	}

	// Parse expected hash from verified checksums
	expectedHash, err := parseChecksumFor(checksums, assetName())
	if err != nil {
		return nil, fmt.Errorf("parse checksum: %w", err)
	}

	// Download archive
	archiveData, err := downloadBytes(archiveAsset.BrowserDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}

	// Verify checksum using appropriate algorithm
	actualHashHex := computeHash(archiveData, checksumFile)
	if actualHashHex != expectedHash {
		return nil, fmt.Errorf("SECURITY: checksum mismatch\n  expected: %s\n  actual:   %s", expectedHash, actualHashHex)
	}

	// Extract binary
	binaryData, err := extractBinary(archiveData, "shellsentry")
	if err != nil {
		return nil, fmt.Errorf("extract binary: %w", err)
	}

	// Determine install path
	installPath := opts.InstallDir
	if installPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("get executable path: %w", err)
		}
		installPath = filepath.Dir(exe)
	}

	targetPath := filepath.Join(installPath, "shellsentry")
	if runtime.GOOS == "windows" {
		targetPath += ".exe"
	}

	// Atomic replace
	if err := atomicReplace(targetPath, binaryData); err != nil {
		return nil, fmt.Errorf("install binary: %w", err)
	}

	result.Updated = true
	result.Message = fmt.Sprintf("Updated from %s to %s", opts.CurrentVersion, newVersion)
	return result, nil
}

func fetchLatestRelease() (*GitHubRelease, error) {
	url := "https://api.github.com/repos/3leaps/shellsentry/releases/latest"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

func findAsset(assets []GitHubAsset, name string) *GitHubAsset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func downloadBytes(url string) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func verifyMinisignSignature(message, signature []byte) error {
	pubkeyStr := EmbeddedMinisignPubkey()
	if pubkeyStr == "" {
		return errors.New("no embedded minisign public key")
	}

	pubkey, err := minisign.NewPublicKey(pubkeyStr)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	sig, err := minisign.DecodeSignature(string(signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	valid, err := pubkey.Verify(message, sig)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}

// computeHash returns the hex-encoded hash of data using the algorithm
// indicated by the checksum filename (SHA2-512SUMS or SHA256SUMS).
func computeHash(data []byte, checksumFile string) string {
	var h hash.Hash
	if strings.Contains(checksumFile, "512") {
		h = sha512.New()
	} else {
		h = sha256.New()
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func parseChecksumFor(checksums []byte, filename string) (string, error) {
	lines := strings.Split(string(checksums), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == filename {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("checksum not found for %s", filename)
}

func extractBinary(archiveData []byte, binaryName string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return extractFromZip(archiveData, binaryName+".exe")
	}
	return extractFromTarGz(archiveData, binaryName)
}

func extractFromTarGz(data []byte, filename string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == filename || filepath.Base(header.Name) == filename {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("file not found in archive: %s", filename)
}

func extractFromZip(data []byte, filename string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	for _, f := range zr.File {
		if f.Name == filename || filepath.Base(f.Name) == filename {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("file not found in archive: %s", filename)
}

func atomicReplace(targetPath string, data []byte) error {
	// Write to temp file in same directory (for atomic rename)
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".shellsentry-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Clean up on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Set executable permissions
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}

	success = true
	return nil
}

func compareVersions(v1, v2 string) (int, error) {
	// Simple semver comparison
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < 3; i++ {
		var n1, n2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &n2)
		}
		if n1 < n2 {
			return -1, nil
		}
		if n1 > n2 {
			return 1, nil
		}
	}
	return 0, nil
}

func isMajorJump(old, new string) bool {
	old = strings.TrimPrefix(old, "v")
	new = strings.TrimPrefix(new, "v")

	var oldMajor, newMajor int
	fmt.Sscanf(old, "%d", &oldMajor)
	fmt.Sscanf(new, "%d", &newMajor)

	return newMajor > oldMajor
}
