BINARY  := salient
PKG     := ./cmd/salient
# Prefer the known-good local toolchain when present; fall back to PATH.
GO      ?= $(if $(wildcard $(HOME)/.local/go/bin/go),$(HOME)/.local/go/bin/go,$(shell command -v go 2>/dev/null || printf go))
GO_ENV  ?= env -u GOROOT GOTOOLCHAIN=auto
GO_PATH  ?= $(if $(wildcard $(HOME)/.local/go/bin/go),$(HOME)/.local/go/bin:,$(EMPTY))
WAILS_VERSION := v2.13.0
TOOLS_DIR ?= .tools
WAILS_BIN_DIR ?= $(TOOLS_DIR)/bin
WAILS_CACHE_DIR ?= $(TOOLS_DIR)/go-build
WAILS   ?= $(abspath $(WAILS_BIN_DIR)/wails)
NFPM_VERSION := v2.47.0
NFPM    ?= $(abspath $(WAILS_BIN_DIR)/nfpm)
LDFLAGS := -s -w
GOOS    ?= $(shell $(GO) env GOOS)
GUI_TAGS ?= $(if $(and $(filter linux,$(GOOS)),$(shell pkg-config --exists webkit2gtk-4.1 2>/dev/null && echo yes)),-tags webkit2_41)

.PHONY: deps gui-deps gui-vendor build gui gui-test test check lint cross package-linux clean integration FORCE

FORCE:

deps:
	$(GO_ENV) $(GO) mod download

# The pinned repo-local wails CLI. A file target so anything needing it
# (gui, gui-deps) self-bootstraps on fresh clones and CI — `make gui` must
# never fail with "no such file" just because gui-deps wasn't run first.
$(WAILS): FORCE
	@if [ ! -x "$@" ] || [ "$$($@ version 2>/dev/null | head -n 1)" != "$(WAILS_VERSION)" ]; then \
		mkdir -p $(WAILS_BIN_DIR) $(WAILS_CACHE_DIR); \
		$(GO_ENV) GOBIN=$(abspath $(WAILS_BIN_DIR)) GOCACHE=$(abspath $(WAILS_CACHE_DIR)) $(GO) install github.com/wailsapp/wails/v2/cmd/wails@$(WAILS_VERSION); \
	fi

# Same self-bootstrap rationale as $(WAILS): package-linux must never fail
# with "no such file" on a fresh clone or CI runner.
$(NFPM):
	mkdir -p $(WAILS_BIN_DIR) $(WAILS_CACHE_DIR)
	$(GO_ENV) GOBIN=$(abspath $(WAILS_BIN_DIR)) GOCACHE=$(abspath $(WAILS_CACHE_DIR)) $(GO) install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

gui-deps: deps gui-vendor $(WAILS)
	cd gui && $(GO_ENV) $(GO) mod download
	cd gui/frontend && npm ci

# web/ is the single source of truth for the vendored map JS (go:embed needs
# it there for the HTML report export). The GUI frontend serves the same files
# from public/vendor/, which is gitignored and reproduced here before any
# frontend build so the two copies can never drift.
gui-vendor:
	mkdir -p gui/frontend/public/vendor
	cp web/*.js gui/frontend/public/vendor/

build:
	CGO_ENABLED=0 $(GO_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

gui: gui-vendor $(WAILS)
	cd gui && PATH="$(GO_PATH)$(PATH)" $(GO_ENV) $(WAILS) build $(GUI_TAGS)

# VERSION drives the .deb/.rpm version string; pass explicitly for real
# releases, e.g. `make package-linux VERSION=0.3.0`.
VERSION ?= 0.0.0-dev

package-linux: gui $(NFPM)
	mkdir -p dist
	cd gui && VERSION=$(VERSION) $(NFPM) package --config nfpm.yaml --packager deb --target $(abspath dist)/
	cd gui && VERSION=$(VERSION) $(NFPM) package --config nfpm.yaml --packager rpm --target $(abspath dist)/

gui-test:
	cd gui && $(GO_ENV) $(GO) test ./...

test:
	$(GO_ENV) $(GO) test -race ./...

# Pre-push gate mirroring CI's blocking checks (minus -race: this dev box
# has no gcc; CI covers the race run). Run before every push.
check:
	@fmt="$$(gofmt -l .)"; if [ -n "$$fmt" ]; then printf '%s\n' "$$fmt" "fix: gofmt -w ."; exit 1; fi
	$(GO_ENV) $(GO) vet ./...
	$(GO_ENV) $(GO) test ./...
	cd gui && $(GO_ENV) $(GO) vet ./... && $(GO_ENV) $(GO) test ./...

lint:
	$(GO_ENV) golangci-lint run ./...

# Hard constraint: pure Go, no cgo, static binaries for all three targets.
# GOFLAGS=-p=2: elastic's typedapi/types package OOM-kills the compiler on
# small (≤4GB) boxes when target builds overlap at full parallelism.
cross:
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=linux   GOARCH=amd64 $(GO_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=darwin  GOARCH=arm64 $(GO_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-darwin-arm64 $(PKG)
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=windows GOARCH=amd64 $(GO_ENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-windows-amd64.exe $(PKG)

# Live-grid check, never in CI. Export SALIENT_ES_URL and SALIENT_API_KEY in
# the environment first; optionally export SALIENT_CA_CERT.
integration: build
	@: "$${SALIENT_ES_URL:?export SALIENT_ES_URL first}"; : "$${SALIENT_API_KEY:?export SALIENT_API_KEY first}"; \
		set --; if [ -n "$${SALIENT_CA_CERT:-}" ]; then set -- --ca-cert "$$SALIENT_CA_CERT"; fi; \
		./bin/$(BINARY) test-connection "$$@"
	@: "$${SALIENT_ES_URL:?export SALIENT_ES_URL first}"; : "$${SALIENT_API_KEY:?export SALIENT_API_KEY first}"; \
		set --; if [ -n "$${SALIENT_CA_CERT:-}" ]; then set -- --ca-cert "$$SALIENT_CA_CERT"; fi; \
		./bin/$(BINARY) discover "$$@"

clean:
	rm -rf bin dist gui/build/bin $(TOOLS_DIR)
