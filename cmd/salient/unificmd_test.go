package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/netconfig"
)

func TestUniFiExportCommand(t *testing.T) {
	const apiKey = "integration-test-key"
	responses := map[string]string{
		"/sites":                             `{"count":1,"data":[{"id":"site-1","internalReference":"default","name":"Default"}],"limit":200,"offset":0,"totalCount":1}`,
		"/sites/site-1/networks":             `{"count":2,"data":[{"id":"net-users"},{"id":"net-servers"}],"limit":200,"offset":0,"totalCount":2}`,
		"/sites/site-1/networks/net-users":   `{"id":"net-users","name":"Users","enabled":true,"vlanId":10,"management":"GATEWAY","ipv4Configuration":{"hostIpAddress":"10.10.0.1","prefixLength":24,"autoScaleEnabled":false}}`,
		"/sites/site-1/networks/net-servers": `{"id":"net-servers","name":"Servers","enabled":true,"vlanId":20,"management":"GATEWAY","ipv4Configuration":{"hostIpAddress":"10.20.0.1","prefixLength":24,"autoScaleEnabled":false}}`,
		"/sites/site-1/devices":              `{"count":1,"data":[{"id":"dev-1","macAddress":"aa:bb:cc:dd:ee:ff","ipAddress":"10.10.0.1","name":"UDM Pro","model":"UDMPRO"}],"limit":200,"offset":0,"totalCount":1}`,
		"/sites/site-1/firewall/zones":       `{"count":2,"data":[{"id":"zone-users","name":"Users","networkIds":["net-users"]},{"id":"zone-servers","name":"Servers","networkIds":["net-servers"]}],"limit":200,"offset":0,"totalCount":2}`,
		"/sites/site-1/firewall/policies":    `{"count":1,"data":[{"id":"policy-1","enabled":true,"name":"Block HTTPS","index":1,"action":{"type":"BLOCK"},"source":{"zoneId":"zone-users"},"destination":{"zoneId":"zone-servers","trafficFilter":{"type":"PORT","portFilter":{"type":"PORTS","matchOpposite":false,"items":[{"type":"PORT_NUMBER","value":443}]}}},"ipProtocolScope":{"ipVersion":"IPV4","protocolFilter":{"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"tcp"}}},"loggingEnabled":true}],"limit":200,"offset":0,"totalCount":1}`,
	}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("X-API-Key"); got != apiKey {
			t.Errorf("X-API-Key = %q", got)
		}
		path := strings.TrimPrefix(r.URL.Path, uniFiIntegrationPath)
		body, ok := responses[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()

	outDir := filepath.Join(t.TempDir(), "unifi")
	t.Setenv(config.EnvUniFiAPIKey, apiKey)
	cmd := newUniFiExportCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--controller", server.URL, "--out-dir", outDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unifi-export: %v\nstderr: %s", err, stderr.String())
	}
	if requests != 7 {
		t.Errorf("request count = %d, want 7", requests)
	}
	if strings.Contains(stdout.String()+stderr.String(), apiKey) {
		t.Fatal("command output leaked API key")
	}

	files := map[string][]byte{}
	for _, name := range []string{
		"unifi-integration-networks.json",
		"unifi-integration-devices.json",
		"unifi-integration-firewall-zones.json",
		"unifi-integration-firewall-policies.json",
	} {
		path := filepath.Join(outDir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(raw), apiKey) {
			t.Fatalf("%s leaked API key", name)
		}
		files[name] = raw
	}
	devs, warnings := netconfig.ParseConfigs(files)
	if len(warnings) != 0 || len(devs) != 1 {
		t.Fatalf("ParseConfigs warnings=%v devices=%+v", warnings, devs)
	}
	dev := devs[0]
	if len(dev.VLANs) != 2 || len(dev.Interfaces) != 1 || len(dev.Rulesets) != 1 || len(dev.Rulesets[0].Rules) != 1 {
		t.Fatalf("exported model = %+v", dev)
	}
	if rule := dev.Rulesets[0].Rules[0]; rule.DstPorts.Lo != 443 || rule.Caveat != "" {
		t.Errorf("exported policy rule = %+v", rule)
	}
}

func TestNormalizeUniFiBaseURL(t *testing.T) {
	if _, err := normalizeUniFiBaseURL("http://192.0.2.10"); err == nil {
		t.Fatal("expected remote plaintext URL rejection")
	}
	got, err := normalizeUniFiBaseURL("https://192.0.2.10/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://192.0.2.10"+uniFiIntegrationPath {
		t.Errorf("base URL = %q", got)
	}
}
