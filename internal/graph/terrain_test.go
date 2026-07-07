package graph_test

import (
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// TestTerrainAddrExcludesNonHosts guards the reported class of bug: pseudo-hosts
// that are not rankable terrain must be excluded so they cannot appear as key
// terrain on the map. 169.254.169.254 (cloud metadata, link-local) was ranking
// #26 on a real scan; loopback and broadcast/multicast must go too.
func TestTerrainAddrExcludesNonHosts(t *testing.T) {
	terrain := []string{"10.0.1.10", "192.168.1.5", "172.16.0.1", "8.8.8.8"}
	notTerrain := []string{
		"169.254.169.254", // cloud metadata / link-local
		"169.254.1.1",     // APIPA link-local
		"127.0.0.1",       // loopback
		"0.0.0.0",         // unspecified
		"255.255.255.255", // limited broadcast
		"224.0.0.251",     // multicast (mDNS)
		"ff02::1",         // IPv6 multicast
		"fe80::1",         // IPv6 link-local
	}
	for _, ip := range terrain {
		if !graph.TerrainAddr(ip) {
			t.Errorf("TerrainAddr(%q) = false, want true (real host)", ip)
		}
	}
	for _, ip := range notTerrain {
		if graph.TerrainAddr(ip) {
			t.Errorf("TerrainAddr(%q) = true, want false (not a rankable host)", ip)
		}
	}
}
