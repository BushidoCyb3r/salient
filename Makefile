BINARY  := defilade
PKG     := ./cmd/defilade
GO      ?= go
WAILS_VERSION := v2.12.0
TOOLS_DIR ?= .tools
WAILS_BIN_DIR ?= $(TOOLS_DIR)/bin
WAILS_CACHE_DIR ?= $(TOOLS_DIR)/go-build
WAILS   ?= $(abspath $(WAILS_BIN_DIR)/wails)
LDFLAGS := -s -w
GOOS    ?= $(shell $(GO) env GOOS)
GUI_TAGS ?= $(if $(and $(filter linux,$(GOOS)),$(shell pkg-config --exists webkit2gtk-4.1 2>/dev/null && echo yes)),-tags webkit2_41)

.PHONY: deps gui-deps build gui gui-test test lint cross clean integration

deps:
	$(GO) mod download

gui-deps: deps
	cd gui && $(GO) mod download
	cd gui/frontend && npm ci
	mkdir -p $(WAILS_BIN_DIR) $(WAILS_CACHE_DIR)
	GOBIN=$(abspath $(WAILS_BIN_DIR)) GOCACHE=$(abspath $(WAILS_CACHE_DIR)) $(GO) install github.com/wailsapp/wails/v2/cmd/wails@$(WAILS_VERSION)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

gui:
	cd gui && $(WAILS) build $(GUI_TAGS)

gui-test:
	cd gui && $(GO) test ./...

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

# Hard constraint: pure Go, no cgo, static binaries for all three targets.
# GOFLAGS=-p=2: elastic's typedapi/types package OOM-kills the compiler on
# small (≤4GB) boxes when target builds overlap at full parallelism.
cross:
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=linux   GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=darwin  GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-darwin-arm64 $(PKG)
	CGO_ENABLED=0 GOFLAGS=-p=2 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-windows-amd64.exe $(PKG)

# Live-grid check, never in CI. Usage:
#   make integration ES_URL=https://manager:9200 API_KEY=... [CA_CERT=grid-ca.pem]
integration: build
	DEFILADE_ES_URL='$(ES_URL)' DEFILADE_API_KEY='$(API_KEY)' \
		./bin/$(BINARY) test-connection $(if $(CA_CERT),--ca-cert $(CA_CERT))
	DEFILADE_ES_URL='$(ES_URL)' DEFILADE_API_KEY='$(API_KEY)' \
		./bin/$(BINARY) discover $(if $(CA_CERT),--ca-cert $(CA_CERT))

clean:
	rm -rf bin gui/build/bin $(TOOLS_DIR)
