BINARY  := defilade
PKG     := ./cmd/defilade
GO      ?= go
WAILS   ?= wails
LDFLAGS := -s -w
GUI_TAGS := $(if $(filter linux,$(shell $(GO) env GOOS)),-tags webkit2_41)

.PHONY: build gui test lint cross clean integration

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

gui:
	cd gui && $(WAILS) build $(GUI_TAGS)

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
	rm -rf bin
