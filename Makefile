-include buildconfig.mk

# Read version from VERSION file, fallback to dev
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
NAME ?= shellsentry
MAIN ?= .

# LDFLAGS for version injection
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)

# Defaults
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT :=
ifeq ($(GOOS),windows)
EXT := .exe
endif

INSTALL_PREFIX ?= $(HOME)
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/.local/bin
ifeq ($(GOOS),windows)
INSTALL_PREFIX ?= $(USERPROFILE)
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin
endif
INSTALL_TARGET ?= $(INSTALL_BINDIR)/$(NAME)$(EXT)
BUILD_ARTIFACT := bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT)
DIST_RELEASE := dist/release
# The release tag is an explicit input (SHELLSENTRY_RELEASE_TAG only).
# A Makefile ?= that lets an inherited bare variable win is a derived input
# and is not accepted (bare RELEASE_TAG is not accepted).
PUBLIC_KEY_NAME ?= shellsentry-release-signing-key.asc
SHELLSENTRY_MINISIGN_KEY ?=
SHELLSENTRY_MINISIGN_PUB ?=
SHELLSENTRY_PGP_KEY_ID ?=
SHELLSENTRY_GPG_HOMEDIR ?=
MINISIGN_PUB_NAME ?= shellsentry-minisign.pub

# Tool installation directory (repo-local)
BIN_DIR := $(CURDIR)/bin

# Pinned tool versions (bootstrap installs these into BIN_DIR; do not float)
# SFETCH_VERSION is a published consumable release (minisig path requires >= v0.4.11).
SFETCH_VERSION := v0.4.15
# Immutable sfetch engine pin (action/repo commit that owns bootstrap-sfetch-verified.sh).
# Coupled with SFETCH_VERSION: advancing the product pin may require a new engine SHA
# when SFETCH_BOOTSTRAP_MAX moves (see sfetch docs/cicd-usage-guide.md).
# Engine is the peeled v0.4.15 tag (c445772), not sfetch's in-tree N-1 pin (v0.4.14).
SFETCH_ENGINE_SHA := c44577261902c848119d3c89b0138becb613b158
SFETCH_ENGINE_SHA256 := 9a074a15db18bca93601e23eca54d411ee72ce69413e802e083f535f8203c79a
# Composite action pin (same commit as engine for this train).
SFETCH_ACTION_SHA := c44577261902c848119d3c89b0138becb613b158
# Engine source repo (flag-owned; no ambient env seam).
SFETCH_ENGINE_REPO := 3leaps/sfetch
# Third-party sfetch pin is docs/security/sfetch-minisign.pub (no Makefile literal).
GONEAT_VERSION ?= v0.6.6
GOVULNCHECK_VERSION ?= v1.6.0
STATICCHECK_VERSION ?= v0.6.1
GOSEC_VERSION ?= v2.29.0

# Host binary extension: Windows installers write sfetch.exe / goneat.exe
HOST_GOOS := $(shell go env GOHOSTOS 2>/dev/null || go env GOOS)
ifeq ($(HOST_GOOS),windows)
BIN_EXT := .exe
else
BIN_EXT :=
endif
SFETCH_LOCAL := $(BIN_DIR)/sfetch$(BIN_EXT)
GONEAT_LOCAL := $(BIN_DIR)/goneat$(BIN_EXT)

# Tool paths (prefer repo-local, fall back to PATH)
SFETCH = $(shell [ -x "$(SFETCH_LOCAL)" ] && echo "$(SFETCH_LOCAL)" || command -v sfetch$(BIN_EXT) 2>/dev/null || command -v sfetch 2>/dev/null)
GONEAT = $(shell [ -x "$(GONEAT_LOCAL)" ] && echo "$(GONEAT_LOCAL)" || command -v goneat$(BIN_EXT) 2>/dev/null || command -v goneat 2>/dev/null)

.PHONY: all help build test clean install fmt fmt-check lint check-all version tools prereqs bootstrap bootstrap-force build-all assess
.PHONY: schema-validate schema-meta sarif-validate precommit prepush govulncheck
.PHONY: gosec gosec-high gosec-install test-gosec-pin test-release-workflow-draft test-workflow-action-pins
.PHONY: release-download release-checksums release-verify-checksums release-sign
.PHONY: release-notes release-create-draft release-upload release-export-key release-export-minisign-key release-export-keys
.PHONY: release-verify-key release-verify-minisign-pubkey release-verify-keys release-verify-signatures release-verify
.PHONY: release-clean bootstrap-script verify-release-key
.PHONY: release-preflight release-guard-tag-version release-prepare-tag-message
.PHONY: release-tag release-push-tag release-verify-tag release-verify-remote-tag
.PHONY: release-publish release-tag-tests require-release-tag
.PHONY: test-release-ci-hygiene test-makefile-release-tag test-upload-release-draft test-release-create-draft
.PHONY: test-release-tag test-release-tag-smartcard test-release-publish test-verify-pinned-tag
.PHONY: test-version-ldflags test-release-preflight test-release-guard-tag-version
.PHONY: test-release-tag-operator test-release-prepare-tag-message test-release-tag-controls
.PHONY: test-release-verify-remote-tag test-release-push-tag
.PHONY: test-release-decernor test-release-stage-tagged-pubkeys test-release-verify-staged-keys
.PHONY: test-ci-install-decernor test-release-verify-committed-anchors
.PHONY: release-insert-anchors release-verify-committed-anchors
.PHONY: package-all print-sfetch-version test-release-verify-checksums test-bootstrap-pin-match test-install-anchor-select
.PHONY: dogfood assert-no-pipe-install-sfetch test-no-pipe-to-shell-docs check-sfetch-pin-freshness
.PHONY: assert-sfetch-pin-coupling assert-tool-pins test-assert-tool-pins test-bootstrap-negative-controls

all: build

# Echo SFETCH_VERSION via make (CI install smoke should not parse Makefile).
print-sfetch-version: ## Print bootstrap pin (SFETCH_VERSION)
	@echo $(SFETCH_VERSION)

help: ## Show this help
	@echo "shellsentry - Static risk assessment for shell scripts"
	@echo "The pause before the pipe."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Current version: $(VERSION)"

# -----------------------------------------------------------------------------
# Bootstrap - Trust Anchor Chain
# -----------------------------------------------------------------------------
#
# Trust chain: verified sfetch engine (digest-pinned) -> sfetch (pinned release)
#              -> goneat (pinned via sfetch --require-minisign)
#
# Does not pipe install-sfetch.sh to bash. Pins land in BIN_DIR.

bootstrap: ## Install development tools via verified trust chain
	@echo "Bootstrapping shellsentry development environment..."
	@echo ""
	@if ! command -v curl >/dev/null 2>&1; then \
		echo "[!!] curl not found (required for bootstrap)"; \
		echo ""; \
		echo "Install curl for your platform:"; \
		echo "  macOS:  brew install curl"; \
		echo "  Ubuntu: sudo apt install curl"; \
		echo "  Fedora: sudo dnf install curl"; \
		exit 1; \
	fi
	@echo "[ok] curl found"
	@echo ""
	@mkdir -p "$(BIN_DIR)"
	@need_sfetch=1; \
	if [ -x "$(SFETCH_LOCAL)" ]; then \
		sf_ver="$$("$(SFETCH_LOCAL)" --version 2>&1 | head -n1 || true)"; \
		if ./scripts/version-matches-pin.sh "$$sf_ver" "$(SFETCH_VERSION)"; then \
			need_sfetch=0; \
			echo "[ok] sfetch $(SFETCH_VERSION) already in $(BIN_DIR)"; \
		else \
			echo "[..] sfetch pin mismatch (have: $$sf_ver; want: $(SFETCH_VERSION)); reinstalling..."; \
			rm -f "$(BIN_DIR)/sfetch" "$(BIN_DIR)/sfetch.exe"; \
		fi; \
	fi; \
	if [ "$$need_sfetch" -eq 1 ]; then \
		echo "[..] Installing sfetch $(SFETCH_VERSION) (verified engine @ $(SFETCH_ENGINE_SHA))..."; \
		./scripts/install-sfetch-verified.sh \
			--version "$(SFETCH_VERSION)" \
			--dir "$(BIN_DIR)" \
			--engine-sha "$(SFETCH_ENGINE_SHA)" \
			--engine-sha256 "$(SFETCH_ENGINE_SHA256)" \
			--repo "$(SFETCH_ENGINE_REPO)"; \
	fi
	@if [ ! -x "$(SFETCH_LOCAL)" ]; then echo "[!!] sfetch installation failed (expected $(SFETCH_LOCAL))"; exit 1; fi
	@echo "[ok] sfetch: $$("$(SFETCH_LOCAL)" --version 2>&1 | head -n1) ($(SFETCH_LOCAL))"
	@echo ""
	@need_goneat=1; \
	if [ -x "$(GONEAT_LOCAL)" ]; then \
		gn_ver="$$("$(GONEAT_LOCAL)" version 2>&1 | head -n1 || true)"; \
		if ./scripts/version-matches-pin.sh "$$gn_ver" "$(GONEAT_VERSION)"; then \
			need_goneat=0; \
			echo "[ok] goneat $(GONEAT_VERSION) already in $(BIN_DIR)"; \
		else \
			echo "[..] goneat pin mismatch (have: $$gn_ver; want: $(GONEAT_VERSION)); reinstalling..."; \
			rm -f "$(BIN_DIR)/goneat" "$(BIN_DIR)/goneat.exe"; \
		fi; \
	fi; \
	if [ "$$need_goneat" -eq 1 ]; then \
		echo "[..] Installing goneat $(GONEAT_VERSION) via sfetch..."; \
		"$(SFETCH_LOCAL)" --repo fulmenhq/goneat --tag $(GONEAT_VERSION) --dest-dir "$(BIN_DIR)" \
			--cache-dir "$(CURDIR)/.cache/sfetch" --require-minisign; \
	fi
	@if [ ! -x "$(GONEAT_LOCAL)" ]; then echo "[!!] goneat installation failed (expected $(GONEAT_LOCAL))"; exit 1; fi
	@echo "[ok] goneat: $$("$(GONEAT_LOCAL)" version 2>&1 | head -n1)"
	@echo ""
	@echo "[..] Installing foundation tools via goneat..."
	@"$(GONEAT_LOCAL)" doctor tools --scope foundation --install --yes 2>/dev/null || \
		echo "[!!] goneat doctor tools failed, some tools may need manual installation"
	@echo ""
	@echo "[ok] Bootstrap complete"
	@echo ""
	@echo "Repo-local tools installed to $(BIN_DIR)"
	@echo "Run 'make build' to build shellsentry"

bootstrap-force: ## Force reinstall repo-local sfetch and goneat, then bootstrap
	@rm -f "$(BIN_DIR)/sfetch" "$(BIN_DIR)/sfetch.exe" "$(BIN_DIR)/goneat" "$(BIN_DIR)/goneat.exe"
	@$(MAKE) bootstrap

tools: ## Verify external tools are available
	@echo "Verifying tools..."
	@# Use goneat doctor if available
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -n "$$GONEAT_BIN" ]; then \
		$$GONEAT_BIN doctor tools --scope foundation 2>&1 || true; \
	else \
		echo "[!!] goneat not found (run 'make bootstrap')"; \
		echo ""; \
		echo "Fallback checks:"; \
		if command -v go >/dev/null 2>&1; then echo "[ok] go: $$(go version | cut -d' ' -f3)"; else echo "[!!] go not found"; fi; \
		if command -v staticcheck >/dev/null 2>&1; then echo "[ok] staticcheck found"; else echo "[!!] staticcheck not found"; fi; \
	fi
	@echo ""

prereqs: tools ## Check prerequisites (alias for tools)

fmt: ## Format code
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -n "$$GONEAT_BIN" ]; then \
		$$GONEAT_BIN format --types go,markdown --folders .; \
	else \
		go fmt ./...; \
		echo "[!!] goneat not found, markdown formatting skipped (run 'make bootstrap')"; \
	fi

fmt-check: ## Check code formatting
	@files=$$(git ls-files '*.go'); \
	if [ -n "$$files" ]; then \
		missing=$$(git ls-files -z '*.go' | xargs -0 gofmt -l); \
		if [ -n "$$missing" ]; then \
			echo "gofmt required for:"; \
			echo "$$missing"; \
			exit 1; \
		fi; \
	fi

lint: ## Run linters (staticcheck pin: STATICCHECK_VERSION)
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

# gosec -version prints "dev" for go install builds (no release ldflags).
# Assert the module version recorded in the binary instead.
gosec-install: ## Install pinned gosec into bin/ and assert its version
	@mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@modver="$$(go version -m "$(BIN_DIR)/gosec" 2>/dev/null | awk '$$1=="mod" && $$2=="github.com/securego/gosec/v2" {print $$3; exit}')"; \
	if [ -z "$$modver" ] || [ "$$modver" != "$(GOSEC_VERSION)" ]; then \
		echo "[!!] gosec version mismatch (have: $$modver; want: $(GOSEC_VERSION))" >&2; \
		exit 1; \
	fi; \
	echo "[ok] gosec $(GOSEC_VERSION) in $(BIN_DIR)"

gosec: ## Run gosec security scanner
	gosec ./...

gosec-high: ## Run gosec (high confidence only)
	@export PATH="$(BIN_DIR):$$PATH"; \
	if ! command -v gosec >/dev/null 2>&1; then \
		echo "[!!] gosec not found on PATH; run 'make gosec-install' (pinned $(GOSEC_VERSION))" >&2; \
		exit 1; \
	fi; \
	modver="$$(go version -m "$$(command -v gosec)" 2>/dev/null | awk '$$1=="mod" && $$2=="github.com/securego/gosec/v2" {print $$3; exit}')"; \
	if [ -z "$$modver" ] || [ "$$modver" != "$(GOSEC_VERSION)" ]; then \
		echo "[!!] gosec version mismatch (have: $$modver; want: $(GOSEC_VERSION))" >&2; \
		exit 1; \
	fi; \
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

test: ## Run tests
	go test -v -race ./...

check-all: fmt-check lint test build ## Run all checks
	@echo "[ok] All checks passed"

govulncheck: ## Run pinned govulncheck vulnerability scan
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

precommit: check-all schema-validate govulncheck ## Local pre-commit checks
	$(MAKE) test-gosec-pin
	$(MAKE) gosec-high
	$(MAKE) release-tag-tests
	$(MAKE) test-no-pipe-to-shell-docs
	@echo "[ok] Pre-commit checks passed"

prepush: precommit sarif-validate test-release-verify-checksums test-bootstrap-pin-match test-install-anchor-select test-assert-tool-pins assert-no-pipe-install-sfetch assert-sfetch-pin-coupling ## Local pre-push checks
	@echo "[ok] Pre-push checks passed"

assess: ## Run goneat assess (format, lint, security)
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN assess --categories format,lint --format concise

build: ## Build for current platform
	@mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="$(LDFLAGS)" \
		-trimpath \
		-o $(BUILD_ARTIFACT) $(MAIN)
	@echo "[ok] Built $(BUILD_ARTIFACT)"

build-all: ## Build for all supported platforms (no darwin/amd64 as of v0.1.5)
	@mkdir -p dist/release
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-arm64     $(MAIN)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-amd64      $(MAIN)
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-arm64      $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-arm64.exe $(MAIN)
	@echo "[ok] Built all platforms to dist/release/"

# Drop any prior-matrix leftovers (e.g. retired darwin/amd64 archives) is inside
# the recipe below so set -eu applies to cleanup + packaging in one shell.
package-all: build-all ## Package release archives in dist/release
	@set -eu; \
	rm -f dist/release/$(NAME)_darwin_amd64.tar.gz \
		dist/release/$(NAME)-darwin-amd64 \
		dist/release/$(NAME)-darwin-amd64.exe; \
	for pair in "darwin arm64" "linux amd64" "linux arm64" "windows amd64" "windows arm64"; do \
		set -- $$pair; \
		os="$$1"; arch="$$2"; \
		base="$(NAME)-$${os}-$${arch}"; \
		asset="$(NAME)_$${os}_$${arch}"; \
		if [ "$$os" = "windows" ]; then \
			archive="$${asset}.zip"; \
			( cd dist/release && cp "$${base}.exe" shellsentry.exe ); \
			zip -j "dist/release/$${archive}" "dist/release/shellsentry.exe"; \
			rm -f "dist/release/shellsentry.exe"; \
		else \
			archive="$${asset}.tar.gz"; \
			( cd dist/release && cp "$${base}" shellsentry ); \
			tar czf "dist/release/$${archive}" -C dist/release shellsentry; \
			rm -f "dist/release/shellsentry"; \
		fi; \
	done; \
	echo "[ok] Packaged archives to dist/release/"

# Tag-consuming recipes refuse a bare RELEASE_TAG (not accepted) and require
# SHELLSENTRY_RELEASE_TAG == v$(VERSION). Expanding $(RELEASE_TAG) here is only to
# detect it. require-release-tag is a real prerequisite so the check runs
# before any other prerequisite of a tag-consuming target.
define require_shellsentry_release_tag
	@if [ "$(origin RELEASE_TAG)" != "undefined" ]; then echo "error: RELEASE_TAG is not accepted; set SHELLSENTRY_RELEASE_TAG only" >&2; exit 1; fi
	@if [ -z "$(SHELLSENTRY_RELEASE_TAG)" ]; then echo "error: SHELLSENTRY_RELEASE_TAG required" >&2; exit 1; fi
	@printf '%s\n' "$(SHELLSENTRY_RELEASE_TAG)" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { echo "error: SHELLSENTRY_RELEASE_TAG must be canonical vX.Y.Z" >&2; exit 1; }
	@if [ "$(SHELLSENTRY_RELEASE_TAG)" != "v$(VERSION)" ]; then echo "error: SHELLSENTRY_RELEASE_TAG ($(SHELLSENTRY_RELEASE_TAG)) must equal v$(VERSION)" >&2; exit 1; fi
endef

require-release-tag:
	$(call require_shellsentry_release_tag)

release-preflight: require-release-tag ## Verify clean-tree pre-tag requirements (does not tag)
	@./scripts/release-preflight.sh

release-guard-tag-version: require-release-tag ## Validate the canonical SHELLSENTRY_RELEASE_TAG
	@./scripts/release-guard-tag-version.sh

release-prepare-tag-message: require-release-tag ## Prepare the external per-cut tag message (maintainer)
	@./scripts/release-tag-operator.sh prepare-message

release-tag: require-release-tag ## Maintainer-only: create and verify a local signed version tag (no push)
	@./scripts/release-tag-operator.sh local-tag

release-push-tag: require-release-tag ## Maintainer-only: publish and verify the signed version tag
	@./scripts/release-tag-operator.sh remote-push

release-verify-tag: require-release-tag ## Verify the tag using only the committed public pin
	@./scripts/verify-pinned-tag.sh

release-verify-remote-tag: require-release-tag ## Compare local and remote tag objects and GitHub verification
	@./scripts/release-verify-remote-tag.sh

release-publish: require-release-tag ## Maintainer-only: byte-verify draft assets, then promote
	@./scripts/release-publish.sh "$(SHELLSENTRY_RELEASE_TAG)" "$(DIST_RELEASE)"

release-download: require-release-tag ## Download release assets for signing
	@mkdir -p $(DIST_RELEASE)
	./scripts/download-release-assets.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

bootstrap-script: ## Copy install script into release directory
	@mkdir -p $(DIST_RELEASE)
	cp scripts/install-shellsentry.sh $(DIST_RELEASE)/install-shellsentry.sh
	@echo "[ok] Copied install-shellsentry.sh to $(DIST_RELEASE)"

release-checksums: bootstrap-script ## Generate SHA256SUMS and SHA512SUMS
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums in dist/release (fail-closed; portable /bin/sh)
	@if [ ! -d "$(DIST_RELEASE)" ]; then echo "error: $(DIST_RELEASE) not found (run make release-download first)" >&2; exit 1; fi
	@echo "Verifying checksums in $(DIST_RELEASE)..."
	@set -eu; \
	cd "$(DIST_RELEASE)"; \
	if [ ! -s SHA256SUMS ]; then \
		echo "error: SHA256SUMS missing or empty in $(DIST_RELEASE)" >&2; \
		exit 1; \
	fi; \
	if [ ! -s SHA512SUMS ]; then \
		echo "error: SHA512SUMS missing or empty in $(DIST_RELEASE)" >&2; \
		exit 1; \
	fi; \
	echo "=== SHA256SUMS ==="; \
	shasum -a 256 -c SHA256SUMS; \
	echo "=== SHA512SUMS ==="; \
	shasum -a 512 -c SHA512SUMS; \
	echo "[ok] Checksum verification complete"

# Negative + positive regression for release-verify-checksums (exit status only).
test-release-verify-checksums: ## Regression: fail-closed checksum verify (corrupt/absent/empty)
	@./scripts/test-release-verify-checksums.sh

# Current-pin vs stale-pin coverage for bootstrap version matching (fixed-string).
test-bootstrap-pin-match: ## Regression: version-matches-pin current + stale cases
	@./scripts/test-bootstrap-pin-match.sh

test-install-anchor-select: ## Regression: installer pin-map anchor selection (unit + coherence)
	@./scripts/test-install-anchor-select.sh

test-gosec-pin: ## Regression: gosec pin and fail-closed missing-binary guard
	@./scripts/test-gosec-pin.sh

test-release-workflow-draft: ## Regression: tag workflow is read-only and artifacts-only
	@python3 ./scripts/test-release-workflow-draft.py

test-release-create-draft: ## Regression: draft GitHub release is created locally, never by CI
	@./scripts/release-create-draft.test.sh

test-workflow-action-pins: ## Regression: every workflow uses: is SHA-pinned
	@python3 ./scripts/test-workflow-action-pins.py

test-release-ci-hygiene: ## Regression: workflows never invoke signing or publish scripts
	@./scripts/test-release-ci-hygiene.sh

test-makefile-release-tag: ## Regression: Makefile refuses bare RELEASE_TAG (not accepted)
	@./scripts/test-makefile-release-tag.sh

test-upload-release-draft: ## Regression: release-upload stays a draft
	@./scripts/test-upload-release-draft.sh

test-version-ldflags: ## Regression: LDFLAGS-injected version outside the repo
	@./scripts/test-version-ldflags.sh

test-release-preflight: ## Regression: preflight refuses a dirty tree and missing inputs
	@./scripts/release-preflight.test.sh

test-release-guard-tag-version: ## Regression: SHELLSENTRY_RELEASE_TAG guard
	@./scripts/release-guard-tag-version.test.sh

test-release-tag-operator: ## Regression: operator loader and dispatch
	@./scripts/release-tag-operator.test.sh

test-release-prepare-tag-message: ## Regression: external tag message preparation
	@./scripts/release-prepare-tag-message.test.sh

test-release-tag-controls: ## Regression: tag identity, message, and ruleset controls
	@./scripts/release-tag-controls.test.sh

test-release-verify-remote-tag: ## Regression: remote tag object and GitHub verification
	@./scripts/release-verify-remote-tag.test.sh

test-release-push-tag: ## Regression: refuse an existing remote tag; verify after push
	@./scripts/release-push-tag.test.sh

test-release-tag: ## Regression: signed tag stays local and refuses GitHub Actions
	@./scripts/test-release-tag.sh

test-release-tag-smartcard: ## Regression: tag signing uses operator GPG home (no secret export)
	@./scripts/test-release-tag-smartcard.sh

test-release-publish: ## Regression: publish promotes only a byte-verified draft
	@./scripts/test-release-publish.sh

test-verify-pinned-tag: ## Regression: signed tag verifies against the committed public pin
	@./scripts/verify-pinned-tag.test.sh

test-release-decernor: ## Regression: ceremony binds Decernor by SHELLSENTRY_DECERNOR_BIN only
	@./scripts/release-decernor.test.sh

test-release-stage-tagged-pubkeys: ## Regression: public keys stage from the tagged commit
	@./scripts/release-stage-tagged-pubkeys.test.sh

test-release-verify-staged-keys: ## Regression: staged keys must match committed anchors
	@./scripts/release-verify-staged-keys.test.sh

test-ci-install-decernor: ## Regression: CI Decernor install prints one stdout path (linux amd64)
	@./scripts/ci-install-decernor.test.sh

test-release-verify-committed-anchors: ## Regression: in-tree anchors mismatch fails (needs SHELLSENTRY_DECERNOR_BIN)
	@./scripts/release-verify-committed-anchors.test.sh

release-insert-anchors: ## Maintainer-only: derive public fingerprint anchors from committed exports
	@./scripts/release-insert-anchors.sh

release-verify-committed-anchors: ## Verify committed public exports against both fingerprint anchors
	@./scripts/release-verify-committed-anchors.sh

release-tag-tests: ## Signed-tag tooling tests (throwaway keys only; never the default homedir)
	@$(MAKE) test-workflow-action-pins
	@$(MAKE) test-release-workflow-draft
	@$(MAKE) test-release-ci-hygiene
	@$(MAKE) test-makefile-release-tag
	@$(MAKE) test-upload-release-draft
	@$(MAKE) test-release-create-draft
	@$(MAKE) test-version-ldflags
	@$(MAKE) test-release-preflight
	@$(MAKE) test-release-guard-tag-version
	@$(MAKE) test-release-tag-operator
	@$(MAKE) test-release-prepare-tag-message
	@$(MAKE) test-release-tag-controls
	@$(MAKE) test-release-verify-remote-tag
	@$(MAKE) test-release-push-tag
	@$(MAKE) test-release-tag
	@$(MAKE) test-release-tag-smartcard
	@$(MAKE) test-release-publish
	@$(MAKE) test-verify-pinned-tag
	@$(MAKE) test-release-decernor
	@$(MAKE) test-release-stage-tagged-pubkeys
	@$(MAKE) test-release-verify-staged-keys
	@echo "[ok] Release tag tooling tests passed"

release-notes: require-release-tag ## Copy release notes into dist/release
	@mkdir -p $(DIST_RELEASE)
	@src="docs/releases/$(SHELLSENTRY_RELEASE_TAG).md"; \
	if [ ! -f "$$src" ]; then \
		echo "error: release notes file $$src not found (did you set SHELLSENTRY_RELEASE_TAG?)" >&2; \
		exit 1; \
	fi; \
	cp "$$src" "$(DIST_RELEASE)/release-notes-$(SHELLSENTRY_RELEASE_TAG).md"
	@echo "[ok] Release notes copied to $(DIST_RELEASE)"

release-sign: require-release-tag ## Sign checksum manifests
	SHELLSENTRY_MINISIGN_KEY=$(SHELLSENTRY_MINISIGN_KEY) SHELLSENTRY_PGP_KEY_ID=$(SHELLSENTRY_PGP_KEY_ID) SHELLSENTRY_GPG_HOMEDIR=$(SHELLSENTRY_GPG_HOMEDIR) ./scripts/sign-release-assets.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

release-export-key: require-release-tag ## Stage PGP public key from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

release-export-minisign-key: require-release-tag ## Stage minisign public key from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

release-export-keys: require-release-tag ## Stage public signing keys from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

verify-release-key: ## Verify PGP key is public-only
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

release-verify-key: verify-release-key ## Verify PGP key is public-only (alias)

release-verify-minisign-pubkey: build ## Verify minisign public key matches embedded trust anchor
	@if [ -z "$(FILE)" ]; then \
		if [ -f "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)" ]; then \
			FILE="$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
		else \
			echo "usage: make release-verify-minisign-pubkey FILE=path/to/key.pub" >&2; exit 1; \
		fi; \
	fi; \
	echo "[verify] Minisign public key: $$FILE"; \
	embedded=$$($(BUILD_ARTIFACT) --self-verify --json 2>/dev/null | grep -o '"minisignPubkey"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4); \
	file_key=$$(cat "$$FILE" 2>/dev/null | tr -d '\n'); \
	if [ -z "$$embedded" ]; then echo "error: could not extract embedded pubkey" >&2; exit 1; fi; \
	if [ -z "$$file_key" ]; then echo "error: could not read $$FILE" >&2; exit 1; fi; \
	if echo "$$file_key" | grep -q "$$embedded"; then \
		echo "[ok] Minisign public key matches embedded trust anchor"; \
	else \
		echo "error: minisign public key does NOT match embedded trust anchor" >&2; \
		echo "  embedded: $$embedded" >&2; \
		echo "  file:     $$file_key" >&2; \
		exit 1; \
	fi

release-verify-keys: ## Verify committed anchors, then both staged public keys against those anchors
	@./scripts/release-verify-committed-anchors.sh
	@./scripts/release-verify-staged-keys.sh $(DIST_RELEASE)

release-verify-signatures: ## Verify minisign and PGP signatures on checksum manifests
	SHELLSENTRY_MINISIGN_PUB=$(SHELLSENTRY_MINISIGN_PUB) SHELLSENTRY_GPG_HOMEDIR=$(SHELLSENTRY_GPG_HOMEDIR) ./scripts/verify-signatures.sh $(DIST_RELEASE)

release-verify: release-verify-checksums release-verify-signatures release-verify-keys ## Full post-signing release verification

release-create-draft: require-release-tag ## Open a draft GitHub release from locally staged packages
	@./scripts/release-create-draft.sh "$(SHELLSENTRY_RELEASE_TAG)" "$(DIST_RELEASE)"

release-upload: require-release-tag release-notes release-verify ## Upload assets (requires full verification chain)
	./scripts/upload-release-assets.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)

release-clean: ## Remove dist/release contents
	rm -rf $(DIST_RELEASE)
	@echo "Cleaned $(DIST_RELEASE)"

SARIF_SCHEMA := schemas/third_party/sarif/sarif-schema-2.1.0.json
SARIF_FIXTURE ?= testdata/benign/heredoc/basic-heredoc.sh

schema-validate: ## Validate schemas folder (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN validate --include schemas/ --format concise

schema-meta: ## Meta-validate JSON Schemas (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN schema validate-schema --schema-id json-schema-2020-12 schemas/shellsentry-report.schema.json; \
	$$GONEAT_BIN schema validate-schema --schema-id json-schema-draft-07 "$(SARIF_SCHEMA)"

sarif-validate: build schema-validate ## Validate SARIF output against SARIF schema (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(GONEAT_LOCAL)" ]; then GONEAT_BIN="$(GONEAT_LOCAL)"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	tmp="$$(mktemp /tmp/shellsentry-sarif.XXXXXX.json)"; \
	trap 'rm -f "$$tmp"' EXIT; \
	"$(BUILD_ARTIFACT)" --format sarif "$(SARIF_FIXTURE)" > "$$tmp"; \
	$$GONEAT_BIN validate data --schema-file "$(SARIF_SCHEMA)" --data "$$tmp" --format json

clean: ## Clean build artifacts
	rm -rf bin/ dist/ coverage.out
	@echo "[ok] Cleaned build artifacts"

install: build ## Install to INSTALL_BINDIR
	@mkdir -p "$(INSTALL_BINDIR)"
	cp "$(BUILD_ARTIFACT)" "$(INSTALL_TARGET)"
ifeq ($(GOOS),windows)
	@echo "[ok] Installed $(NAME)$(EXT) to $(INSTALL_TARGET)"
else
	chmod 755 "$(INSTALL_TARGET)"
	@echo "[ok] Installed $(NAME)$(EXT) to $(INSTALL_TARGET)"
endif

version: ## Show current version
	@echo "$(VERSION)"

# -----------------------------------------------------------------------------
# Version Management
# -----------------------------------------------------------------------------

version-check: ## Show current version (verbose)
	@echo "Current version: $(VERSION)"

version-set: ## Set version (usage: make version-set V=X.Y.Z)
	@if [ -z "$(V)" ]; then echo "usage: make version-set V=X.Y.Z" >&2; exit 1; fi
	@echo "$(V)" > VERSION
	@echo "[ok] Version set to $(V)"

version-patch: ## Bump patch version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	newpatch=$$((patch + 1)); \
	newver="$$major.$$minor.$$newpatch"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

version-minor: ## Bump minor version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	newminor=$$((minor + 1)); \
	newver="$$major.$$newminor.0"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

version-major: ## Bump major version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	newmajor=$$((major + 1)); \
	newver="$$newmajor.0.0"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

# -----------------------------------------------------------------------------
# Dogfood / hygiene assertions
# -----------------------------------------------------------------------------
# Authenticity (signatures) is handled by verified bootstrap / sfetch --require-minisign.
# Dogfood is complementary: behavior analysis of the install script after fetch.

assert-no-pipe-install-sfetch: ## Fail if install-sfetch.sh is still piped to bash/sh
	@./scripts/assert-no-pipe-install-sfetch.sh

test-no-pipe-to-shell-docs: ## Regression: docs do not recommend curl piped to a shell
	@./scripts/test-no-pipe-to-shell-docs.sh

assert-sfetch-pin-coupling: ## Fail if CI action SHA/version drift from Makefile pins
	@./scripts/assert-sfetch-pin-coupling.sh

assert-tool-pins: ## Exact sfetch/goneat pin check (stderr-aware)
	@./scripts/assert-tool-pins.sh "$(SFETCH_VERSION)" "$(GONEAT_VERSION)"

test-assert-tool-pins: ## Regression: pin check does not SIGPIPE on extra version lines
	@./scripts/test-assert-tool-pins.sh

test-bootstrap-negative-controls: ## Consumer negative controls (digest/tamper/anchor/freshness/dogfood)
	@./scripts/test-bootstrap-negative-controls.sh

check-sfetch-pin-freshness: ## Soft-warn if SFETCH_VERSION is behind latest (informational only)
	@./scripts/check-sfetch-pin-freshness.sh "$(SFETCH_VERSION)"

dogfood: build ## Fetch sfetch installer via verified sfetch, analyze with shellsentry
	@echo "Dogfood: fetch install-sfetch.sh with sfetch, analyze with shellsentry..."
	@SFETCH_BIN=""; \
	if [ -x "$(SFETCH_LOCAL)" ]; then SFETCH_BIN="$(SFETCH_LOCAL)"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch not found (run make bootstrap)"; exit 1; fi; \
	tmpdir="$$(mktemp -d)"; \
	$$SFETCH_BIN --repo 3leaps/sfetch --tag $(SFETCH_VERSION) \
		--asset-match "install-sfetch.sh" --dest-dir "$$tmpdir" \
		--cache-dir "$$tmpdir/sfetch-cache" --require-minisign; \
	script="$$(find "$$tmpdir" -name 'install-sfetch.sh' 2>/dev/null | head -n1)"; \
	if [ -z "$$script" ] || [ ! -s "$$script" ]; then echo "[!!] failed to fetch install-sfetch.sh"; rm -rf "$$tmpdir"; exit 1; fi; \
	./$(BUILD_ARTIFACT) --exit-on-danger "$$script"; \
	rm -rf "$$tmpdir"; \
	echo "[ok] sfetch install script passed shellsentry analysis"
