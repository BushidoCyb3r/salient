package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/config"
)

func TestAnalyzeCommandWritesProtectedArtifact(t *testing.T) {
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"summary\":\"No material findings\",\"findings\":[]}"}}]}`)
	}))
	defer server.Close()
	t.Setenv(config.EnvAssistAPIKey, "secret")

	cmd := newAnalyzeCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--endpoint", server.URL, "--model", "local-test"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(stdout.String())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode = %o, want 600", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("No material findings")) || !strings.Contains(stderr.String(), "Handling reminder") {
		t.Fatalf("missing result or warning: body=%s stderr=%s", body, stderr.String())
	}
	if auth != "Bearer secret" {
		t.Fatalf("authorization header = %q", auth)
	}
}
