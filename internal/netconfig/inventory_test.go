package netconfig

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// fixture: 6 nodes across 3 subnets, one MAC-only match; 2 declared devices.
func fixture() (graph.Snapshot, []DeclaredDevice) {
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{ZeroCovCIDRs: []string{"10.0.9.0/24"}},
		Nodes: []graph.Node{
			{IP: "10.0.1.1", Subnet: "10.0.1.0/24"},                            // cisco gw (IP observed)
			{IP: "10.0.1.10", Subnet: "10.0.1.0/24", MAC: "aa:bb:cc:dd:ee:ff"}, // unifi ap (by MAC)
			{IP: "10.0.1.20", Subnet: "10.0.1.0/24"},                           // host
			{IP: "10.0.2.30", Subnet: "10.0.2.0/24"},                           // host; gw 10.0.2.1 NOT observed
			{IP: "10.0.2.31", Subnet: "10.0.2.0/24"},                           // host
			{IP: "10.0.3.5", Subnet: "10.0.3.0/24"},                            // undeclared subnet
		},
	}
	devs := []DeclaredDevice{
		{
			Source: "core.cfg", Vendor: "cisco-ios", Hostname: "core-rtr",
			Interfaces: []Interface{
				{Name: "Gi0/0", Prefixes: []string{"10.0.1.1/24"}},
				{Name: "Gi0/1", Prefixes: []string{"10.0.2.1/24"}},
				{Name: "Gi0/2", Prefixes: []string{"10.0.9.1/24"}}, // silent, in blind spot
				{Name: "Gi0/3", Prefixes: []string{"10.0.4.1/24"}, Shutdown: true},
			},
		},
		{
			Source: "unifi.json", Vendor: "unifi", Hostname: "ap-01",
			Interfaces: []Interface{{Name: "ap-01", MAC: "aa:bb:cc:dd:ee:ff"}}, // MAC-only
		},
	}
	return snap, devs
}

func TestDiffInventory(t *testing.T) {
	snap, devs := fixture()
	got := DiffInventory(snap, devs)

	want := InventoryResult{
		Matches: []DeviceMatch{
			{Device: "ap-01", Source: "unifi.json", IPs: []string{"10.0.1.10"}, ByMAC: true},
			{Device: "core-rtr", DeviceType: "Cisco IOS router", Source: "core.cfg", IPs: []string{"10.0.1.1"}, ByMAC: false}, // 10.0.2.1 gw IP not observed
		},
		AdoptedDevices:   []AdoptedDevice{{Name: "ap-01", ObservedIP: "10.0.1.10"}},
		DeclaredGateways: map[string]string{"10.0.1.1": "core-rtr", "10.0.2.1": "core-rtr"},
		SilentSubnets:    []SilentSubnet{{CIDR: "10.0.9.0/24", Device: "core-rtr", InBlindSpot: true}},
		UndeclaredCIDRs:  []string{"10.0.3.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DiffInventory mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestDiffInventoryCiscoSwitchGatewayClassification(t *testing.T) {
	snap := graph.Snapshot{Nodes: []graph.Node{
		{IP: "10.0.40.2", Subnet: "10.0.40.0/24"},
		{IP: "10.0.40.10", Subnet: "10.0.40.0/24"},
	}}
	switchDevice := DeclaredDevice{
		Source: "access-sw.cfg", Vendor: "cisco-ios", Hostname: "access-sw-01",
		Interfaces: []Interface{
			{Name: "Vlan40", Prefixes: []string{"10.0.40.2/24"}},
			{Name: "Gi0/1", Switchport: true, VLAN: 40},
		},
	}

	l2 := DiffInventory(snap, []DeclaredDevice{switchDevice})
	if len(l2.Matches) != 1 || l2.Matches[0].DeviceType != "Cisco IOS switch" {
		t.Fatalf("L2 switch match = %+v", l2.Matches)
	}
	if _, ok := l2.DeclaredGateways["10.0.40.2"]; ok {
		t.Errorf("L2 management SVI incorrectly declared as gateway: %+v", l2.DeclaredGateways)
	}

	switchDevice.Routing = true
	l3 := DiffInventory(snap, []DeclaredDevice{switchDevice})
	if len(l3.Matches) != 1 || l3.Matches[0].DeviceType != "Cisco IOS Layer 3 switch" {
		t.Fatalf("L3 switch match = %+v", l3.Matches)
	}
	if l3.DeclaredGateways["10.0.40.2"] != "access-sw-01" {
		t.Errorf("L3 switch SVI missing from declared gateways: %+v", l3.DeclaredGateways)
	}
}

func TestDeclaredDeviceIdentityRecognizesSVIOnlySwitch(t *testing.T) {
	typ, canRoute := declaredDeviceIdentity(DeclaredDevice{
		Vendor: "cisco-ios", Interfaces: []Interface{{Name: "Vlan1", Prefixes: []string{"10.0.0.2/24"}}},
	})
	if typ != "Cisco IOS switch" || canRoute {
		t.Fatalf("SVI-only identity = (%q, %v), want L2 switch", typ, canRoute)
	}
}

func TestDiffInventoryDeterministic(t *testing.T) {
	snap, devs := fixture()
	if a, b := DiffInventory(snap, devs), DiffInventory(snap, devs); !reflect.DeepEqual(a, b) {
		t.Errorf("nondeterministic output:\n a=%+v\n b=%+v", a, b)
	}
}

func TestDiffInventoryEmpty(t *testing.T) {
	got := DiffInventory(graph.Snapshot{}, nil)
	if len(got.Matches) != 0 || len(got.SilentSubnets) != 0 || len(got.UndeclaredCIDRs) != 0 {
		t.Errorf("empty input should yield empty result, got %+v", got)
	}
	if got.DeclaredGateways == nil {
		t.Error("DeclaredGateways should be non-nil for JSON stability")
	}
}
