package config

import "testing"

// TestNamedPortClasses pins the port→name→class table: every classified
// port must have a human name, and spot-checked ports must land in the
// intended class so a table edit can't silently reshuffle the map legend.
func TestNamedPortClasses(t *testing.T) {
	for port := range portClass {
		if KnownService(port) == "" {
			t.Errorf("port %d has a class but no service name", port)
		}
	}
	checks := []struct {
		port  uint16
		name  string
		class ServiceClass
	}{
		{88, "kerberos", ClassAuth},
		{3268, "ldap-gc", ClassAuth},
		{9389, "adws", ClassAuth},
		{1812, "radius", ClassAuth},
		{5353, "mdns", ClassName},
		{3702, "ws-discovery", ClassName},
		{2049, "nfs", ClassFile},
		{21, "ftp", ClassFile},
		{6379, "redis", ClassDB},
		{1434, "mssql-browser", ClassDB},
		{9200, "elasticsearch", ClassDB},
		{8006, "proxmox", ClassWeb},
		{8530, "wsus", ClassWeb},
		{6443, "kubernetes", ClassWeb},
		{5900, "vnc", ClassAdmin},
		{5985, "winrm", ClassAdmin},
		{2375, "docker", ClassAdmin},
		// Named but deliberately ClassOther.
		{25, "smtp", ClassOther},
		{554, "rtsp", ClassOther},
		{631, "ipp", ClassOther},
		{9100, "jetdirect", ClassOther},
		{135, "msrpc", ClassOther},
		{1883, "mqtt", ClassOther},
		{161, "snmp", ClassOther},
		// Network-vendor protocols.
		{5246, "capwap", ClassOther},
		{8211, "papi", ClassOther},
		{4786, "smart-install", ClassOther},
		{49, "tacacs", ClassOther},
		{6789, "unifi-speedtest", ClassOther},
		{4343, "aruba-https", ClassWeb},
		{7734, "meraki-cloud", ClassOther},
		{3221, "jms", ClassOther},
		{2083, "radsec", ClassOther},
	}
	for _, c := range checks {
		if got := KnownService(c.port); got != c.name {
			t.Errorf("KnownService(%d) = %q, want %q", c.port, got, c.name)
		}
		if got := ServiceName(c.port); got != c.name {
			t.Errorf("ServiceName(%d) = %q, want %q", c.port, got, c.name)
		}
		if got := ClassForPort(c.port); got != c.class {
			t.Errorf("ClassForPort(%d) = %v, want %v", c.port, got, c.class)
		}
	}
	// Unknown ports: no name from KnownService, port-N fallback from ServiceName.
	if got := KnownService(49152); got != "" {
		t.Errorf("KnownService(49152) = %q, want empty", got)
	}
	if got := ServiceName(49152); got != "port-49152" {
		t.Errorf("ServiceName(49152) = %q", got)
	}
}

func TestNetworkGearPorts(t *testing.T) {
	for _, p := range []uint16{5246, 5247, 8211, 4786, 49, 6789, 8880} {
		if !IsNetworkGearPort(p) {
			t.Errorf("port %d should be a network-gear port", p)
		}
	}
	for _, p := range []uint16{161, 1812, 443, 22} { // shared by endpoints
		if IsNetworkGearPort(p) {
			t.Errorf("port %d must not trigger NetworkGear (endpoints use it)", p)
		}
	}
}
