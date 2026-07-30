// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// VerifyInfo contains information for self-verification.
type VerifyInfo struct {
	Version      string           `json:"version"`
	Platform     string           `json:"platform"`
	BuildTime    string           `json:"buildTime"`
	GitCommit    string           `json:"gitCommit"`
	IsDev        bool             `json:"isDev"`
	Asset        string           `json:"asset,omitempty"`
	HashAlgo     string           `json:"hashAlgo,omitempty"`
	ExpectedHash string           `json:"expectedHash,omitempty"`
	HashError    string           `json:"hashError,omitempty"`
	URLs         *VerifyURLs      `json:"urls,omitempty"`
	TrustAnchor  *TrustAnchorInfo `json:"trustAnchor"`
	Commands     *VerifyCommands  `json:"commands,omitempty"`
}

// VerifyURLs contains release URLs for verification.
type VerifyURLs struct {
	SHA512SUMS        string `json:"sha512sums"`
	SHA512SUMSMinisig string `json:"sha512sumsMinisig"`
	SHA256SUMS        string `json:"sha256sums"`
	SHA256SUMSMinisig string `json:"sha256sumsMinisig"`
}

// TrustAnchorInfo contains embedded trust anchor information.
type TrustAnchorInfo struct {
	MinisignPubkey string `json:"minisignPubkey"`
	KeyID          string `json:"keyId"`
}

// VerifyCommands contains platform-specific verification commands.
type VerifyCommands struct {
	Checksum string `json:"checksum"`
	Minisign string `json:"minisign"`
}

// PrintSelfVerify outputs verification instructions.
func PrintSelfVerify(w io.Writer, version, buildTime, gitCommit string, jsonOutput bool) {
	info := buildVerifyInfo(version, buildTime, gitCommit)

	if jsonOutput {
		printVerifyJSON(w, info)
		return
	}

	printVerifyText(w, info)
}

func buildVerifyInfo(version, buildTime, gitCommit string) *VerifyInfo {
	info := &VerifyInfo{
		Version:   version,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		BuildTime: buildTime,
		GitCommit: gitCommit,
		IsDev:     version == "dev" || version == "",
		TrustAnchor: &TrustAnchorInfo{
			MinisignPubkey: EmbeddedMinisignPubkey(),
			KeyID:          EmbeddedMinisignKeyID(),
		},
	}

	if info.IsDev {
		return info
	}

	info.Asset = assetName()
	baseURL := fmt.Sprintf("https://github.com/3leaps/shellsentry/releases/download/v%s", version)
	info.URLs = &VerifyURLs{
		SHA512SUMS:        baseURL + "/SHA512SUMS",
		SHA512SUMSMinisig: baseURL + "/SHA512SUMS.minisig",
		SHA256SUMS:        baseURL + "/SHA256SUMS",
		SHA256SUMSMinisig: baseURL + "/SHA256SUMS.minisig",
	}

	// Try to fetch expected hash (prefer SHA512SUMS)
	expectedHash, hashAlgo, err := fetchExpectedHash(version, info.Asset)
	if err != nil {
		info.HashError = err.Error()
	} else {
		info.ExpectedHash = expectedHash
		info.HashAlgo = hashAlgo
	}

	info.Commands = &VerifyCommands{
		Checksum: checksumCommand(info.HashAlgo),
		Minisign: minisignCommand(version, info.TrustAnchor.MinisignPubkey, info.HashAlgo),
	}

	return info
}

// platformKey returns "goos_goarch" for the given pair (pure helper for tests).
func platformKey(goos, goarch string) string {
	return goos + "_" + goarch
}

// assetNameFor returns the release archive name for goos/goarch.
func assetNameFor(goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("shellsentry_%s_%s%s", goos, goarch, ext)
}

func assetName() string {
	return assetNameFor(runtime.GOOS, runtime.GOARCH)
}

// LastDarwinAMD64Tag is the last release that published darwin/amd64 artifacts.
const LastDarwinAMD64Tag = "v0.1.4"

// isDarwinAMD64 reports whether the platform pair is Intel Mac.
func isDarwinAMD64(goos, goarch string) bool {
	return goos == "darwin" && goarch == "amd64"
}

// darwinAMD64RetirementMessage explains how to recover after the platform drop.
func darwinAMD64RetirementMessage(targetTag string) string {
	if targetTag == "" {
		targetTag = "latest"
	}
	return fmt.Sprintf(
		"shellsentry %s does not ship darwin/amd64 (Intel Mac) artifacts. "+
			"darwin/amd64 was retired after %s. "+
			"Pin the last supporting release with the installer: "+
			"curl -fsSL https://github.com/3leaps/shellsentry/releases/download/%s/install-shellsentry.sh | bash -s -- --tag %s  "+
			"Or build from source: GOOS=darwin GOARCH=amd64 go build -o shellsentry .",
		targetTag, LastDarwinAMD64Tag, LastDarwinAMD64Tag, LastDarwinAMD64Tag,
	)
}

func checksumCommand(hashAlgo string) string {
	if hashAlgo == "sha512" {
		switch runtime.GOOS {
		case "darwin":
			return "shasum -a 512 $(which shellsentry)"
		case "windows":
			return "Get-FileHash (Get-Command shellsentry).Source -Algorithm SHA512"
		default:
			return "sha512sum $(which shellsentry)"
		}
	}
	// Default to SHA256
	switch runtime.GOOS {
	case "darwin":
		return "shasum -a 256 $(which shellsentry)"
	case "windows":
		return "Get-FileHash (Get-Command shellsentry).Source -Algorithm SHA256"
	default:
		return "sha256sum $(which shellsentry)"
	}
}

func minisignCommand(version, pubkey, hashAlgo string) string {
	checksumFile := "SHA256SUMS"
	if hashAlgo == "sha512" {
		checksumFile = "SHA512SUMS"
	}
	return fmt.Sprintf(`curl -sL https://github.com/3leaps/shellsentry/releases/download/v%s/%s -o /tmp/%s
curl -sL https://github.com/3leaps/shellsentry/releases/download/v%s/%s.minisig -o /tmp/%s.minisig
minisign -Vm /tmp/%s -P %s`, version, checksumFile, checksumFile, version, checksumFile, checksumFile, checksumFile, pubkey)
}

func fetchExpectedHash(version, asset string) (hash, algo string, err error) {
	baseURL := fmt.Sprintf("https://github.com/3leaps/shellsentry/releases/download/v%s", version)
	client := &http.Client{Timeout: 10 * time.Second}

	// Try SHA512SUMS first
	checksumFiles := []struct {
		name string
		algo string
	}{
		{"SHA512SUMS", "sha512"},
		{"SHA256SUMS", "sha256"},
	}

	for _, cf := range checksumFiles {
		url := baseURL + "/" + cf.name
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		// Parse checksum format: "hash  filename"
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] == asset {
				return parts[0], cf.algo, nil
			}
		}
	}

	return "", "", fmt.Errorf("asset %s not found in checksums", asset)
}

func printVerifyText(w io.Writer, info *VerifyInfo) {
	_, _ = fmt.Fprintf(w, "\nshellsentry %s (%s)\n", info.Version, info.Platform)
	_, _ = fmt.Fprintf(w, "Built: %s\n", info.BuildTime)
	_, _ = fmt.Fprintf(w, "Commit: %s\n", info.GitCommit)

	if info.IsDev {
		_, _ = fmt.Fprintln(w, "\nThis is a development build. No published checksums available.")
		_, _ = fmt.Fprintln(w, "To verify a release build, install from: https://github.com/3leaps/shellsentry/releases")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Embedded trust anchors:")
		_, _ = fmt.Fprintf(w, "  Minisign pubkey: %s\n", info.TrustAnchor.MinisignPubkey)
		_, _ = fmt.Fprintf(w, "  Key ID: %s\n", info.TrustAnchor.KeyID)
		return
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Release URLs:")
	_, _ = fmt.Fprintf(w, "  SHA512SUMS:         %s\n", info.URLs.SHA512SUMS)
	_, _ = fmt.Fprintf(w, "  SHA512SUMS.minisig: %s\n", info.URLs.SHA512SUMSMinisig)
	_, _ = fmt.Fprintf(w, "  SHA256SUMS:           %s\n", info.URLs.SHA256SUMS)
	_, _ = fmt.Fprintf(w, "  SHA256SUMS.minisig:   %s\n", info.URLs.SHA256SUMSMinisig)

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Expected asset: %s\n", info.Asset)

	_, _ = fmt.Fprintln(w)
	if info.HashError != "" {
		_, _ = fmt.Fprintln(w, "Expected hash: (network unavailable - fetch manually from URLs above)")
	} else {
		algoLabel := "SHA256"
		if info.HashAlgo == "sha512" {
			algoLabel = "SHA512"
		}
		_, _ = fmt.Fprintf(w, "Expected %s (fetched from release):\n", algoLabel)
		_, _ = fmt.Fprintf(w, "  %s\n", info.ExpectedHash)
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Verify checksum externally:")
	switch runtime.GOOS {
	case "darwin":
		_, _ = fmt.Fprintln(w, "  # macOS")
	case "windows":
		_, _ = fmt.Fprintln(w, "  # Windows (PowerShell)")
	default:
		_, _ = fmt.Fprintln(w, "  # Linux")
	}
	_, _ = fmt.Fprintf(w, "  %s\n", info.Commands.Checksum)

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Verify signature with minisign:")
	for _, line := range strings.Split(info.Commands.Minisign, "\n") {
		_, _ = fmt.Fprintf(w, "  %s\n", line)
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Embedded trust anchors:")
	_, _ = fmt.Fprintf(w, "  Minisign pubkey: %s\n", info.TrustAnchor.MinisignPubkey)
	_, _ = fmt.Fprintf(w, "  Key ID: %s\n", info.TrustAnchor.KeyID)

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "WARNING: A compromised binary could lie. Run these commands yourself.")
}

func printVerifyJSON(w io.Writer, info *VerifyInfo) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}
