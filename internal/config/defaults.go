// Package config centralizes every tunable threshold and default in
// Salient. No magic numbers inline anywhere else (SALIENT_PLAN.md §15).
package config

import (
	"strconv"
	"time"
)

// Environment variable names. Auth material goes through the environment,
// never shell history.
const (
	EnvESURL        = "SALIENT_ES_URL"
	EnvAPIKey       = "SALIENT_API_KEY"
	EnvAssistAPIKey = "SALIENT_AI_API_KEY"
)

// Elasticsearch client defaults.
const (
	// HTTPTimeout bounds any single ES round trip.
	HTTPTimeout = 90 * time.Second
	// DiscoverWindow is the default lookback for `discover` dataset counts.
	DiscoverWindow = 7 * 24 * time.Hour
	// DatasetTermsSize caps the dataset terms aggregation; a grid with
	// more distinct datasets than this only affects the discovery listing.
	DatasetTermsSize = 200
	// SensorTermsSize caps the observer.name terms aggregation.
	SensorTermsSize = 100
)

// Output handling (SALIENT_PLAN.md §14): topology artifacts are sensitive.
const (
	OutputDirMode  = 0o700
	OutputFileMode = 0o600
	DataDirName    = "salient-data"
)

// Optional snapshot analysis. This path is never used unless the operator
// explicitly invokes `analyze`.
const (
	AssistMaxNodes         = 100
	AssistMaxEdges         = 500
	AssistMaxResponseBytes = 4 << 20
	AssistTimeout          = 90 * time.Second
)

// Scan defaults.
const (
	DefaultWindow           = 14 * 24 * time.Hour // §11 scan --window default
	CompositePageSize       = 1000                // §6.1 composite agg page size
	DefaultMaxEdges         = 500_000             // §6.1 --max-edges safety limit
	ResponderTermsSize      = 2000                // role-evidence responder terms cap
	RoleSampleHostsSize     = 3                   // example client IPs kept per responder for evidence strings
	TopNTemporal            = 50                  // §6.1 second-pass temporal for top-N nodes
	TerrainEvidenceTopN     = 20                  // ranked nodes carrying explicit score-driver rationale
	ExactBetweennessMax     = 2000                // §10 gonum exact ≤2k nodes
	BetweennessSamplePivots = 256                 // Brandes–Pich pivots above the exact limit
)

// Map generation (SALIENT_PLAN.md §8).
const (
	GroupPrefixV4         = 24   // §8.2 default subnet grouping prefix
	SparseGroupMinHosts   = 2    // groups below this collapse into "sparse"
	GatewayMACMinIPs      = 10   // §8.4 K: MAC answering for ≥K IPs = gateway
	GatewayMACTermsSize   = 50   // §8.4 candidate responder MACs sampled per sensor
	MapMinConns           = 5    // §8.5 noise floor default
	ClientAggMaxComposite = 0.15 // §8.5 clients below this composite aggregate
	MapTargetElements     = 60   // §8.5 readability target
	MapMaxElements        = 120  // above this, unfocused maps condense to an overview
	MapOverviewTopNodes   = 20   // (legacy) global top-N; superseded by per-segment retention
	MapOverviewMaxGroups  = 12   // (legacy) global group cap; superseded by MapSegmentMaxGroups
	MapAllPrivateCap      = 1500 // "show all private" ceiling: promote at most this many RFC1918 hosts before the rest re-aggregate
	MapSegmentTopHosts    = 5    // segment-flow map: named hosts kept per VLAN box (rest → "N more hosts")
	MapSegmentMaxGroups   = 64   // segment-flow map: max VLAN boxes before the least-active overflow to "other internal networks"
)

// Drift detection (SALIENT_PLAN.md Phase 2).
const (
	DriftRankDelta = 5
	DriftTopN      = 20
)

// MapPalette is the fixed §8.5 service-class palette, identical in every
// product and documented in docs/MAPS.md.
var MapPalette = map[ServiceClass]string{
	ClassAuth:  "#d95f30", // auth: red-orange
	ClassName:  "#3d7edb", // name resolution: blue
	ClassFile:  "#3f9d5a", // file: green
	ClassDB:    "#8858c8", // db: purple
	ClassWeb:   "#8a8f98", // web: gray
	ClassAdmin: "#d8a02e", // admin RDP/SSH: yellow
	ClassOther: "#c3c7cd", // other: light gray
}

// ClassLabel names a service class for legends.
func ClassLabel(c ServiceClass) string {
	switch c {
	case ClassAuth:
		return "auth"
	case ClassName:
		return "name resolution"
	case ClassFile:
		return "file"
	case ClassDB:
		return "database"
	case ClassWeb:
		return "web"
	case ClassAdmin:
		return "admin (RDP/SSH)"
	}
	return "other"
}

// Temporal classification thresholds (SALIENT_PLAN.md §9).
const (
	TemporalSparseMax     = 10   // <10 conns in window = Sparse
	TemporalDominantFrac  = 0.80 // "≥80% of volume" rule shared by classes
	TemporalConstantHours = 20   // activity in ≥20/24 hour buckets = Constant
	BusinessStartHour     = 8    // 0800 local
	BusinessEndHour       = 18   // 1800 local
	NightWindowHours      = 3    // Nightly: ≤3h window
	NightStartHour        = 20   // night = 2000–0600 local
	NightEndHour          = 6
)

// Role inference thresholds (SALIENT_PLAN.md §7). Every magic number here.
const (
	RoleDCMinKerberosClients  = 5
	RoleDNSMinClients         = 5
	RoleFileMinClients        = 3
	RoleDBMinClients          = 2
	RoleWebMinClients         = 5
	RoleJumpMaxInDegree       = 3
	RoleJumpMinOutDegree      = 5
	RolePrinterMinClients     = 1
	RoleCameraMinClients      = 1
	RoleMailMinClients        = 2
	RoleNetworkGearMinClients = 1
)

// Scoring weights (SALIENT_PLAN.md §10). Sum ≈ 1.0.
const (
	WeightDependency = 0.40
	WeightPageRank   = 0.25
	WeightBetween    = 0.20
	WeightSubnet     = 0.15

	PageRankDamping   = 0.85
	PageRankTolerance = 1e-6
	AuthEdgeWeightMul = 3.0 // §10 auth/dns edges weighted ×3
)

// ServiceClass buckets a responder port into a coarse dependency class. Used
// by scoring (critical/auth weighting) and, later, map edge coloring (§8.5).
type ServiceClass int

const (
	ClassOther ServiceClass = iota
	ClassAuth               // kerberos, ldap
	ClassName               // dns
	ClassFile               // smb
	ClassDB
	ClassWeb
	ClassAdmin // rdp, ssh
)

// portClass maps well-known responder ports to a service class. Service is
// derived from the port rather than a separate ES sub-agg to keep the
// composite aggregation cheap.
var portClass = map[uint16]ServiceClass{
	// auth (incl. AD global catalog + AD web services)
	88: ClassAuth, 389: ClassAuth, 636: ClassAuth, 464: ClassAuth,
	1812: ClassAuth, 749: ClassAuth, 3268: ClassAuth, 3269: ClassAuth,
	9389: ClassAuth,
	// name / discovery
	53: ClassName, 5353: ClassName, 137: ClassName, 3702: ClassName,
	// file
	445: ClassFile, 139: ClassFile, 2049: ClassFile, 548: ClassFile,
	21: ClassFile, 873: ClassFile,
	// db / data infrastructure
	1433: ClassDB, 3306: ClassDB, 5432: ClassDB, 1521: ClassDB,
	1434: ClassDB, 6379: ClassDB, 27017: ClassDB, 9200: ClassDB,
	5984: ClassDB, 8086: ClassDB, 9092: ClassDB, 5672: ClassDB,
	11211: ClassDB,
	// web (incl. common self-hosted UIs)
	80: ClassWeb, 443: ClassWeb, 8080: ClassWeb, 8443: ClassWeb,
	8000: ClassWeb, 8888: ClassWeb, 3000: ClassWeb, 8006: ClassWeb,
	32400: ClassWeb, 8123: ClassWeb, 5000: ClassWeb, 9090: ClassWeb,
	10443: ClassWeb, 8843: ClassWeb, 8530: ClassWeb, 8531: ClassWeb,
	6443: ClassWeb, 4343: ClassWeb,
	// admin
	3389: ClassAdmin, 22: ClassAdmin, 5900: ClassAdmin, 5901: ClassAdmin,
	5902: ClassAdmin, 23: ClassAdmin, 5985: ClassAdmin, 5986: ClassAdmin,
	830: ClassAdmin, 1494: ClassAdmin, 2598: ClassAdmin, 2375: ClassAdmin,
	2376: ClassAdmin,
	// named but ClassOther (mail, mgmt, iot, av) — zero value, listed in
	// portName only.
}

// portName gives every classified or otherwise notable responder port a
// short human label. Ports here but absent from portClass are deliberately
// ClassOther (mail, snmp, iot, av…).
var portName = map[uint16]string{
	88: "kerberos", 389: "ldap", 636: "ldaps", 464: "kpasswd",
	1812: "radius", 749: "kadmin", 3268: "ldap-gc", 3269: "ldaps-gc",
	9389: "adws",
	53:   "dns", 5353: "mdns", 137: "netbios-ns", 3702: "ws-discovery",
	445: "smb", 139: "netbios", 2049: "nfs", 548: "afp", 21: "ftp", 873: "rsync",
	1433: "mssql", 3306: "mysql", 5432: "postgres", 1521: "oracle",
	1434: "mssql-browser", 6379: "redis", 27017: "mongodb",
	9200: "elasticsearch", 5984: "couchdb", 8086: "influxdb", 9092: "kafka",
	5672: "amqp", 11211: "memcached",
	80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt",
	8000: "http-alt", 8888: "http-alt", 3000: "grafana", 8006: "proxmox",
	32400: "plex", 8123: "home-assistant", 5000: "upnp/octoprint", 9090: "prometheus",
	10443: "unifi", 8843: "unifi-guest", 8530: "wsus", 8531: "wsus-tls",
	6443: "kubernetes",
	3389: "rdp", 22: "ssh", 5900: "vnc", 5901: "vnc", 5902: "vnc",
	23: "telnet", 5985: "winrm", 5986: "winrm-tls", 830: "netconf",
	1494: "citrix-ica", 2598: "citrix-cgp", 2375: "docker", 2376: "docker-tls",
	25: "smtp", 465: "smtps", 587: "submission", 110: "pop3", 995: "pop3s",
	143: "imap", 993: "imaps",
	123: "ntp", 161: "snmp", 162: "snmp-trap", 514: "syslog", 69: "tftp",
	67: "dhcp", 68: "dhcp", 1900: "ssdp",
	631: "ipp", 9100: "jetdirect",
	554:  "rtsp",
	1883: "mqtt", 8883: "mqtts",
	5060: "sip", 5061: "sips",
	135: "msrpc", 593: "rpc-http", 902: "vmware",
	500: "ike", 4500: "ipsec-nat", 1723: "pptp", 1194: "openvpn", 51820: "wireguard",
	25565: "minecraft",
	// Network-vendor protocols (UniFi, Cisco, Aruba, Meraki, Juniper).
	5246: "capwap", 5247: "capwap-data", 8211: "papi", 4786: "smart-install",
	49: "tacacs", 1645: "radius-legacy", 1646: "radius-legacy-acct",
	6789: "unifi-speedtest", 8880: "unifi-http", 10001: "unifi-discovery", 3478: "stun",
	4343: "aruba-https", 2083: "radsec", 7734: "meraki-cloud", 9350: "meraki-mtunnel",
	3221: "jms", 7804: "juniper-space", 546: "dhcpv6", 547: "dhcpv6",
}

// networkGearPorts are served only by controllers, switches, and APs —
// never by ordinary endpoints — so a responder here is network gear.
var networkGearPorts = map[uint16]bool{
	5246: true, 5247: true, // capwap (WLC <-> AP)
	8211: true,             // aruba papi
	4786: true,             // cisco smart-install
	49:   true,             // tacacs+
	6789: true, 8880: true, // unifi
}

// IsNetworkGearPort reports whether a responder port implies network gear.
func IsNetworkGearPort(port uint16) bool { return networkGearPorts[port] }

// ClassForPort returns the service class of a responder port.
func ClassForPort(port uint16) ServiceClass { return portClass[port] }

// KnownService returns the short label for a recognized responder port, or
// "" when the port is not notable — callers building service lists use this
// to skip ephemeral/unknown ports.
func KnownService(port uint16) string { return portName[port] }

// ServiceName returns a short human label for a responder port, falling
// back to "port-N" for unrecognized ports.
func ServiceName(port uint16) string {
	if n := portName[port]; n != "" {
		return n
	}
	return "port-" + strconv.Itoa(int(port))
}

// IsCriticalDependency reports whether traffic to this port counts toward the
// critical in-degree score (§10: auth/dns/smb/db services).
func IsCriticalDependency(port uint16) bool {
	switch ClassForPort(port) {
	case ClassAuth, ClassName, ClassFile, ClassDB:
		return true
	}
	return false
}

// IsAuthEdge reports whether an edge to this port gets the ×3 PageRank weight.
func IsAuthEdge(port uint16) bool {
	c := ClassForPort(port)
	return c == ClassAuth || c == ClassName
}

// IsAdminPort reports RDP/SSH, used by jump-box shape inference.
func IsAdminPort(port uint16) bool { return ClassForPort(port) == ClassAdmin }
