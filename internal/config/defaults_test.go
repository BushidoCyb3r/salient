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
