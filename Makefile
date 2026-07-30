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
RELEASE_TAG ?= $(if $(SHELLSENTRY_RELEASE_TAG),$(SHELLSENTRY_RELEASE_TAG),$(shell git describe --tags --abbrev=0 2>/dev/null || echo v$(VERSION)))
PUBLIC_KEY_NAME ?= shellsentry-release-signing-key.asc
SHELLSENTRY_MINISIGN_KEY ?=
SHELLSENTRY_MINISIGN_PUB ?=
SHELLSENTRY_PGP_KEY_ID ?=
SHELLSENTRY_GPG_HOMEDIR ?=
MINISIGN_PUB_NAME ?= shellsentry-minisign.pub

# Tool installation directory (repo-local)
BIN_DIR := $(CURDIR)/bin

# Pinned tool versions (bootstrap installs these into BIN_DIR; do not float)
SFETCH_VERSION := v0.4.9
GONEAT_VERSION ?= v0.5.15
GOVULNCHECK_VERSION ?= v1.6.0

# Tool paths (prefer repo-local, fall back to PATH)
SFETCH = $(shell [ -x "$(BIN_DIR)/sfetch" ] && echo "$(BIN_DIR)/sfetch" || command -v sfetch 2>/dev/null)
GONEAT = $(shell [ -x "$(BIN_DIR)/goneat" ] && echo "$(BIN_DIR)/goneat" || command -v goneat 2>/dev/null)

.PHONY: all help build test clean install fmt fmt-check lint check-all version tools prereqs bootstrap bootstrap-force build-all assess
.PHONY: schema-validate schema-meta sarif-validate precommit prepush govulncheck
.PHONY: release-download release-checksums release-verify-checksums release-sign
.PHONY: release-notes release-upload release-export-key release-export-minisign-key release-export-keys
.PHONY: release-verify-key release-verify-minisign-pubkey release-verify-keys release-verify-signatures release-verify
.PHONY: release-clean bootstrap-script verify-release-key
.PHONY: package-all print-sfetch-version test-release-verify-checksums

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
# Trust chain: curl -> sfetch (pinned release) -> goneat (pinned via sfetch)
#
# Pins land in BIN_DIR. Stale PATH copies are ignored when a repo-local binary
# is present; bootstrap reinstalls when the local binary version does not match
# the declared pin.

bootstrap: ## Install development tools via trust chain
	@echo "Bootstrapping shellsentry development environment..."
	@echo ""
	@# Step 0: Verify curl is available (required trust anchor)
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
	@# Step 1: Install sfetch at declared pin into BIN_DIR
	@mkdir -p "$(BIN_DIR)"
	@need_sfetch=1; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then \
		sf_ver="$$("$(BIN_DIR)/sfetch" --version 2>/dev/null | head -n1 || true)"; \
		pin="$(SFETCH_VERSION)"; pin_nov="$${pin#v}"; \
		if echo "$$sf_ver" | grep -Eq "$$pin|$$pin_nov"; then \
			need_sfetch=0; \
			echo "[ok] sfetch $(SFETCH_VERSION) already in $(BIN_DIR)"; \
		else \
			echo "[..] sfetch pin mismatch (have: $$sf_ver; want: $(SFETCH_VERSION)); reinstalling..."; \
			rm -f "$(BIN_DIR)/sfetch"; \
		fi; \
	fi; \
	if [ "$$need_sfetch" -eq 1 ]; then \
		echo "[..] Installing sfetch $(SFETCH_VERSION) (trust anchor)..."; \
		curl -fsSL https://github.com/3leaps/sfetch/releases/download/$(SFETCH_VERSION)/install-sfetch.sh | bash -s -- \
			--dir "$(BIN_DIR)" --tag "$(SFETCH_VERSION)" --require-minisign; \
	fi
	@if [ ! -x "$(BIN_DIR)/sfetch" ]; then echo "[!!] sfetch installation failed"; exit 1; fi
	@echo "[ok] sfetch: $$("$(BIN_DIR)/sfetch" --version 2>&1 | head -n1) ($(BIN_DIR)/sfetch)"
	@echo ""
	@# Step 2: Install goneat at declared pin into BIN_DIR via sfetch
	@need_goneat=1; \
	if [ -x "$(BIN_DIR)/goneat" ]; then \
		gn_ver="$$("$(BIN_DIR)/goneat" version 2>/dev/null | head -n1 || true)"; \
		if echo "$$gn_ver" | grep -Eq "$(GONEAT_VERSION)|$${GONEAT_VERSION#v}"; then \
			need_goneat=0; \
			echo "[ok] goneat $(GONEAT_VERSION) already in $(BIN_DIR)"; \
		else \
			echo "[..] goneat pin mismatch (have: $$gn_ver; want: $(GONEAT_VERSION)); reinstalling..."; \
			rm -f "$(BIN_DIR)/goneat"; \
		fi; \
	fi; \
	if [ "$$need_goneat" -eq 1 ]; then \
		echo "[..] Installing goneat $(GONEAT_VERSION) via sfetch..."; \
		"$(BIN_DIR)/sfetch" --repo fulmenhq/goneat --tag $(GONEAT_VERSION) --dest-dir "$(BIN_DIR)" \
			--cache-dir "$(CURDIR)/.cache/sfetch" --require-minisign; \
	fi
	@if [ ! -x "$(BIN_DIR)/goneat" ]; then echo "[!!] goneat installation failed"; exit 1; fi
	@echo "[ok] goneat: $$("$(BIN_DIR)/goneat" version 2>&1 | head -n1)"
	@echo ""
	@# Step 3: Install foundation tools via goneat (best-effort locally)
	@echo "[..] Installing foundation tools via goneat..."
	@"$(BIN_DIR)/goneat" doctor tools --scope foundation --install --yes 2>/dev/null || \
		echo "[!!] goneat doctor tools failed, some tools may need manual installation"
	@echo ""
	@echo "[ok] Bootstrap complete"
	@echo ""
	@echo "Repo-local tools installed to $(BIN_DIR)"
	@echo "Run 'make build' to build shellsentry"

bootstrap-force: ## Force reinstall repo-local sfetch and goneat, then bootstrap
	@rm -f "$(BIN_DIR)/sfetch" "$(BIN_DIR)/goneat"
	@$(MAKE) bootstrap

tools: ## Verify external tools are available
	@echo "Verifying tools..."
	@# Use goneat doctor if available
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
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
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
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

lint: ## Run linters
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "[!!] staticcheck not found, skipping (run 'make bootstrap')"; \
	fi

test: ## Run tests
	go test -v -race ./...

check-all: fmt-check lint test build ## Run all checks
	@echo "[ok] All checks passed"

govulncheck: ## Run pinned govulncheck vulnerability scan
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

precommit: check-all schema-validate govulncheck ## Local pre-commit checks
	@echo "[ok] Pre-commit checks passed"

prepush: precommit sarif-validate test-release-verify-checksums ## Local pre-push checks
	@echo "[ok] Pre-push checks passed"

assess: ## Run goneat assess (format, lint, security)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
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

package-all: build-all ## Package release archives in dist/release
	@set -euo pipefail; \
	# Drop any prior-matrix leftovers (e.g. retired darwin/amd64 archives).
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

release-download: ## Download release assets for signing
	@mkdir -p $(DIST_RELEASE)
	./scripts/download-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

bootstrap-script: ## Copy install script into release directory
	@mkdir -p $(DIST_RELEASE)
	cp scripts/install-shellsentry.sh $(DIST_RELEASE)/install-shellsentry.sh
	@echo "[ok] Copied install-shellsentry.sh to $(DIST_RELEASE)"

release-checksums: bootstrap-script ## Generate SHA256SUMS and SHA512SUMS
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums in dist/release (fail-closed)
	@if [ ! -d "$(DIST_RELEASE)" ]; then echo "error: $(DIST_RELEASE) not found (run make release-download first)" >&2; exit 1; fi
	@echo "Verifying checksums in $(DIST_RELEASE)..."
	@set -euo pipefail; \
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

release-notes: ## Copy release notes into dist/release
	@if [ -z "$(RELEASE_TAG)" ]; then echo "error: RELEASE_TAG not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@src="docs/releases/$(RELEASE_TAG).md"; \
	if [ ! -f "$$src" ]; then \
		echo "error: release notes file $$src not found (did you set RELEASE_TAG?)" >&2; \
		exit 1; \
	fi; \
	cp "$$src" "$(DIST_RELEASE)/release-notes-$(RELEASE_TAG).md"
	@echo "[ok] Release notes copied to $(DIST_RELEASE)"

release-sign: release-checksums ## Sign checksum manifests
	SHELLSENTRY_MINISIGN_KEY=$(SHELLSENTRY_MINISIGN_KEY) SHELLSENTRY_PGP_KEY_ID=$(SHELLSENTRY_PGP_KEY_ID) SHELLSENTRY_GPG_HOMEDIR=$(SHELLSENTRY_GPG_HOMEDIR) ./scripts/sign-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-export-key: ## Export PGP public key to dist/release
	SHELLSENTRY_GPG_HOMEDIR=$(SHELLSENTRY_GPG_HOMEDIR) ./scripts/export-release-key.sh $(SHELLSENTRY_PGP_KEY_ID) $(DIST_RELEASE)

release-export-minisign-key: ## Copy minisign public key to dist/release
	@if [ -z "$(SHELLSENTRY_MINISIGN_KEY)" ] && [ -z "$(SHELLSENTRY_MINISIGN_PUB)" ]; then echo "SHELLSENTRY_MINISIGN_KEY or SHELLSENTRY_MINISIGN_PUB not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@# Use explicit pub path if set, otherwise derive from secret key path
	@if [ -n "$(SHELLSENTRY_MINISIGN_PUB)" ]; then \
		pubkey="$(SHELLSENTRY_MINISIGN_PUB)"; \
	else \
		pubkey="$$(echo "$(SHELLSENTRY_MINISIGN_KEY)" | sed 's/\\.key$$/.pub/')"; \
	fi; \
	if [ -f "$$pubkey" ]; then \
		cp "$$pubkey" "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
		echo "[ok] Copied minisign public key to $(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
	else \
		echo "error: public key $$pubkey not found" >&2; \
		exit 1; \
	fi

release-export-keys: release-export-minisign-key release-export-key ## Export all public signing keys

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

release-verify-keys: release-verify-key ## Verify all exported public keys
	@if [ -f "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)" ]; then \
		$(MAKE) release-verify-minisign-pubkey FILE=$(DIST_RELEASE)/$(MINISIGN_PUB_NAME); \
	else \
		echo "[skip] No minisign public key in $(DIST_RELEASE)"; \
	fi

release-verify-signatures: ## Verify minisign and PGP signatures on checksum manifests
	SHELLSENTRY_MINISIGN_PUB=$(SHELLSENTRY_MINISIGN_PUB) SHELLSENTRY_GPG_HOMEDIR=$(SHELLSENTRY_GPG_HOMEDIR) ./scripts/verify-signatures.sh $(DIST_RELEASE)

release-verify: release-verify-checksums release-verify-signatures release-verify-keys ## Full post-signing release verification

release-upload: release-notes release-verify ## Upload assets (requires full verification chain)
	./scripts/upload-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-clean: ## Remove dist/release contents
	rm -rf $(DIST_RELEASE)
	@echo "Cleaned $(DIST_RELEASE)"

SARIF_SCHEMA := schemas/third_party/sarif/sarif-schema-2.1.0.json
SARIF_FIXTURE ?= testdata/benign/heredoc/basic-heredoc.sh

schema-validate: ## Validate schemas folder (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN validate --include schemas/ --format concise

schema-meta: ## Meta-validate JSON Schemas (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN schema validate-schema --schema-id json-schema-2020-12 schemas/shellsentry-report.schema.json; \
	$$GONEAT_BIN schema validate-schema --schema-id json-schema-draft-07 "$(SARIF_SCHEMA)"

sarif-validate: build schema-validate ## Validate SARIF output against SARIF schema (goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
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
# Dogfood Target (future)
# -----------------------------------------------------------------------------
# Once shellsentry is functional, this target validates the sfetch install script
# using shellsentry itself - completing the trust chain.

dogfood: build ## Validate sfetch install script with shellsentry
	@echo "Validating sfetch install script with shellsentry..."
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch not found"; exit 1; fi; \
	$$SFETCH_BIN --repo 3leaps/sfetch --latest --asset-match "install-sfetch.sh" --output - \
		| ./$(BUILD_ARTIFACT) --exit-on-danger; \
	echo "[ok] sfetch install script passed shellsentry analysis"
