package escli

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestFetchNodeMACsExcludesGateways(t *testing.T) {
	// 10.0.0.5 has its own NIC MAC (aa…). 10.0.0.6 and 10.0.0.7 both answer
	// with the gateway MAC (bb…), which also appears for many other IPs —
	// the top-level MAC-IP-count agg reports it over the gateway threshold,
	// so it must be excluded from per-node attribution.
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":100}},"aggregations":{
			"by_ip":{"buckets":[
				{"key":"10.0.0.5","top_mac":{"buckets":[{"key":"aa:aa:aa:00:00:01"}]}},
				{"key":"10.0.0.6","top_mac":{"buckets":[{"key":"bb:bb:bb:00:00:01"}]}},
				{"key":"10.0.0.7","top_mac":{"buckets":[{"key":"bb:bb:bb:00:00:01"}]}}
			]},
			"gw_macs":{"buckets":[
				{"key":"bb:bb:bb:00:00:01","ips":{"value":20}},
				{"key":"aa:aa:aa:00:00:01","ips":{"value":1}}
			]}
		}}`),
	})
	got, err := cli.FetchNodeMACs(context.Background(), DefaultFieldMap(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got["10.0.0.5"] != "aa:aa:aa:00:00:01" {
		t.Errorf("host MAC not attributed: %q", got["10.0.0.5"])
	}
	if _, ok := got["10.0.0.6"]; ok {
		t.Errorf("gateway MAC must not be attributed to 10.0.0.6")
	}
	if _, ok := got["10.0.0.7"]; ok {
		t.Errorf("gateway MAC must not be attributed to 10.0.0.7")
	}
}
