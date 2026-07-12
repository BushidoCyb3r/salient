package escli

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestFetchDHCPLeases(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":10}},"aggregations":{"by_ip":{
			"buckets":[
				{"key":"172.16.10.164","top_hostname":{"buckets":[{"key":"livingroom-g4-instant"}]},"top_mac":{"buckets":[{"key":"1c:6a:1b:81:76:ef"}]}},
				{"key":"172.16.10.25","top_hostname":{"buckets":[]},"top_mac":{"buckets":[{"key":"e0:5a:1b:d8:24:44"}]}},
				{"key":"172.16.10.99","top_hostname":{"buckets":[]},"top_mac":{"buckets":[]}}
			]}}}`),
	})
	leases, err := cli.FetchDHCPLeases(context.Background(), DefaultFieldMap(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("want 2 leases (the empty one dropped), got %+v", leases)
	}
	if got := leases["172.16.10.164"]; got.Hostname != "livingroom-g4-instant" || got.MAC != "1c:6a:1b:81:76:ef" {
		t.Errorf("bad lease for .164: %+v", got)
	}
	if got := leases["172.16.10.25"]; got.Hostname != "" || got.MAC != "e0:5a:1b:d8:24:44" {
		t.Errorf("bad lease for .25 (no hostname sent, MAC only): %+v", got)
	}
	if _, ok := leases["172.16.10.99"]; ok {
		t.Error("lease with neither hostname nor MAC should be dropped, not returned empty")
	}
}

func TestFetchDHCPLeasesNoDataset(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":0}},"aggregations":{}}`),
	})
	fm := DefaultFieldMap()
	fm.Datasets.DHCP = nil
	leases, err := cli.FetchDHCPLeases(context.Background(), fm, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Errorf("want empty map when DHCP dataset absent, got %+v", leases)
	}
}
