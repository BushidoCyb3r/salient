package main

import (
	"os"
	"strings"
	"testing"
)

func TestFrontendSelfContainedAndHasExpectedMarkers(t *testing.T) {
	html, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile("frontend/src/main.js")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(html) + string(js)
	for _, want := range []string{"cytoscape", "cxttap", "drift-new", "ListSnapshots", "LoadModel", "Legend", "Connect", "RunScan", "CancelScan", "ExportMap", "ExportImage", "SuggestTags", "cy.png", "exportfmt", "scan:progress", "scan:done", "connect:warning", "connform", "tasklog", "snapshot:open", "snapshots:refresh", "ai-provider", "ai-endpoint", "ai-model", "ai-key", "ai-egress", "ai-tagbtn", "suggested_tags"} {
		if !strings.Contains(combined, want) {
			t.Errorf("frontend missing %q", want)
		}
	}
	if strings.Contains(string(html), `src="http`) {
		t.Error("index.html loads an external resource — must be fully self-contained")
	}
}
