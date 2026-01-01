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

# Pinned tool versions (minimums; existing installs are respected)
SFETCH_VERSION := v0.3.1
GONEAT_VERSION := v0.4.0

# Tool paths (prefer repo-local, fall back to PATH)
SFETCH = $(shell [ -x "$(BIN_DIR)/sfetch" ] && echo "$(BIN_DIR)/sfetch" || command -v sfetch 2>/dev/null)
GONEAT = $(shell [ -x "$(BIN_DIR)/goneat" ] && echo "$(BIN_DIR)/goneat" || command -v goneat 2>/dev/null)

.PHONY: all help build test clean install fmt fmt-check lint check-all version tools prereqs bootstrap bootstrap-force build-all assess
.PHONY: schema-validate schema-meta sarif-validate precommit prepush
.PHONY: release-download release-checksums release-verify-checksums release-sign release-notes release-upload release-export-key release-export-minisign-key release-clean bootstrap-script verify-release-key
.PHONY: package-all

all: build

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
# Trust chain: curl -> sfetch -> (future: shellsentry validates install scripts!)
#
# sfetch (3leaps/sfetch) is the trust anchor - a minimal, auditable binary fetcher.
# Once shellsentry is functional, we'll use it to validate sfetch's install script
# before execution - eating our own dogfood.

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
	@# Step 1: Install sfetch (trust anchor)
	@mkdir -p "$(BIN_DIR)"
	@if [ ! -x "$(BIN_DIR)/sfetch" ] && ! command -v sfetch >/dev/null 2>&1; then \
		echo "[..] Installing sfetch (trust anchor)..."; \
		curl -fsSL https://github.com/3leaps/sfetch/releases/download/$(SFETCH_VERSION)/install-sfetch.sh | bash -s -- --dest "$(BIN_DIR)"; \
	else \
		echo "[ok] sfetch already installed"; \
	fi
	@# Verify sfetch
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch installation failed"; exit 1; fi; \
	echo "[ok] sfetch: $$SFETCH_BIN"
	@echo ""
	@# Step 2: Install goneat via sfetch
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ ! -x "$(BIN_DIR)/goneat" ] && ! command -v goneat >/dev/null 2>&1; then \
		echo "[..] Installing goneat $(GONEAT_VERSION) via sfetch..."; \
		$$SFETCH_BIN --repo fulmenhq/goneat --tag $(GONEAT_VERSION) --dest-dir "$(BIN_DIR)"; \
	else \
		echo "[ok] goneat already installed"; \
	fi
	@# Verify goneat
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat installation failed"; exit 1; fi; \
	echo "[ok] goneat: $$($$GONEAT_BIN version 2>&1 | head -n1)"
	@echo ""
	@# Step 3: Install foundation tools via goneat
	@echo "[..] Installing foundation tools via goneat..."
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	$$GONEAT_BIN doctor tools --scope foundation --install --yes 2>/dev/null || \
		echo "[!!] goneat doctor tools failed, some tools may need manual installation"
	@echo ""
	@# Future: Step 4 - use shellsentry to validate scripts before execution
	@# Once shellsentry is functional:
	@#   $$SFETCH_BIN --repo 3leaps/sfetch --asset-match "install-sfetch.sh" --output - | ./bin/shellsentry --exit-on-danger
	@echo "[ok] Bootstrap complete"
	@echo ""
	@echo "Repo-local tools installed to $(BIN_DIR)"
	@echo "Run 'make build' to build shellsentry"

bootstrap-force: ## Force reinstall all tools
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

precommit: check-all schema-validate ## Local pre-commit checks
	@echo "[ok] Pre-commit checks passed"

prepush: precommit sarif-validate ## Local pre-push checks
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

build-all: ## Build for all platforms
	@mkdir -p dist/release
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-amd64     $(MAIN)
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-arm64     $(MAIN)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-amd64      $(MAIN)
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-arm64      $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)
	@echo "[ok] Built all platforms to dist/release/"

package-all: build-all ## Package release archives in dist/release
	@set -euo pipefail; \
	for pair in "darwin amd64" "darwin arm64" "linux amd64" "linux arm64" "windows amd64"; do \
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

release-checksums: bootstrap-script ## Generate SHA256SUMS and SHA2-512SUMS
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums in dist/release
	@if [ ! -d "$(DIST_RELEASE)" ]; then echo "error: $(DIST_RELEASE) not found (run make release-download first)" >&2; exit 1; fi
	@echo "Verifying checksums in $(DIST_RELEASE)..."
	@cd $(DIST_RELEASE) && \
	if [ -f SHA256SUMS ]; then \
		echo "=== SHA256SUMS ===" && \
		shasum -a 256 -c SHA256SUMS 2>&1 | grep -v ': OK$$' || echo "All SHA256 checksums OK"; \
	fi && \
	if [ -f SHA2-512SUMS ]; then \
		echo "=== SHA2-512SUMS ===" && \
		shasum -a 512 -c SHA2-512SUMS 2>&1 | grep -v ': OK$$' || echo "All SHA512 checksums OK"; \
	fi
	@echo "[ok] Checksum verification complete"

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

verify-release-key: ## Verify PGP key is public-only
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

release-upload: release-notes verify-release-key ## Upload assets and update release notes
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
