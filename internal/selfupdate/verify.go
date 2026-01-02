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
	Checksum  string `json:"checksum"`
	Minisign  string `json:"minisign"`
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
		SHA512SUMS:        baseURL + "/SHA2-512SUMS",
		SHA512SUMSMinisig: baseURL + "/SHA2-512SUMS.minisig",
		SHA256SUMS:        baseURL + "/SHA256SUMS",
		SHA256SUMSMinisig: baseURL + "/SHA256SUMS.minisig",
	}

	// Try to fetch expected hash (prefer SHA2-512SUMS)
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

func assetName() string {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("shellsentry_%s_%s%s", runtime.GOOS, runtime.GOARCH, ext)
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
		checksumFile = "SHA2-512SUMS"
	}
	return fmt.Sprintf(`curl -sL https://github.com/3leaps/shellsentry/releases/download/v%s/%s -o /tmp/%s
curl -sL https://github.com/3leaps/shellsentry/releases/download/v%s/%s.minisig -o /tmp/%s.minisig
minisign -Vm /tmp/%s -P %s`, version, checksumFile, checksumFile, version, checksumFile, checksumFile, checksumFile, pubkey)
}

func fetchExpectedHash(version, asset string) (hash, algo string, err error) {
	baseURL := fmt.Sprintf("https://github.com/3leaps/shellsentry/releases/download/v%s", version)
	client := &http.Client{Timeout: 10 * time.Second}

	// Try SHA2-512SUMS first
	checksumFiles := []struct {
		name string
		algo string
	}{
		{"SHA2-512SUMS", "sha512"},
		{"SHA256SUMS", "sha256"},
	}

	for _, cf := range checksumFiles {
		url := baseURL + "/" + cf.name
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		body, err := io.ReadAll(resp.Body)
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
	fmt.Fprintf(w, "\nshellsentry %s (%s)\n", info.Version, info.Platform)
	fmt.Fprintf(w, "Built: %s\n", info.BuildTime)
	fmt.Fprintf(w, "Commit: %s\n", info.GitCommit)

	if info.IsDev {
		fmt.Fprintln(w, "\nThis is a development build. No published checksums available.")
		fmt.Fprintln(w, "To verify a release build, install from: https://github.com/3leaps/shellsentry/releases")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Embedded trust anchors:")
		fmt.Fprintf(w, "  Minisign pubkey: %s\n", info.TrustAnchor.MinisignPubkey)
		fmt.Fprintf(w, "  Key ID: %s\n", info.TrustAnchor.KeyID)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Release URLs:")
	fmt.Fprintf(w, "  SHA2-512SUMS:         %s\n", info.URLs.SHA512SUMS)
	fmt.Fprintf(w, "  SHA2-512SUMS.minisig: %s\n", info.URLs.SHA512SUMSMinisig)
	fmt.Fprintf(w, "  SHA256SUMS:           %s\n", info.URLs.SHA256SUMS)
	fmt.Fprintf(w, "  SHA256SUMS.minisig:   %s\n", info.URLs.SHA256SUMSMinisig)

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Expected asset: %s\n", info.Asset)

	fmt.Fprintln(w)
	if info.HashError != "" {
		fmt.Fprintln(w, "Expected hash: (network unavailable - fetch manually from URLs above)")
	} else {
		algoLabel := "SHA256"
		if info.HashAlgo == "sha512" {
			algoLabel = "SHA512"
		}
		fmt.Fprintf(w, "Expected %s (fetched from release):\n", algoLabel)
		fmt.Fprintf(w, "  %s\n", info.ExpectedHash)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Verify checksum externally:")
	switch runtime.GOOS {
	case "darwin":
		fmt.Fprintln(w, "  # macOS")
	case "windows":
		fmt.Fprintln(w, "  # Windows (PowerShell)")
	default:
		fmt.Fprintln(w, "  # Linux")
	}
	fmt.Fprintf(w, "  %s\n", info.Commands.Checksum)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Verify signature with minisign:")
	for _, line := range strings.Split(info.Commands.Minisign, "\n") {
		fmt.Fprintf(w, "  %s\n", line)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Embedded trust anchors:")
	fmt.Fprintf(w, "  Minisign pubkey: %s\n", info.TrustAnchor.MinisignPubkey)
	fmt.Fprintf(w, "  Key ID: %s\n", info.TrustAnchor.KeyID)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "WARNING: A compromised binary could lie. Run these commands yourself.")
}

func printVerifyJSON(w io.Writer, info *VerifyInfo) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}
