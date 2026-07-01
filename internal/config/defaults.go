// Package config centralizes every tunable threshold and default in
// Defilade. No magic numbers inline anywhere else (DEFILADE_PLAN.md §15).
package config

import (
	"strconv"
	"time"
)

// Environment variable names. Auth material goes through the environment,
// never shell history.
const (
	EnvESURL  = "DEFILADE_ES_URL"
	EnvAPIKey = "DEFILADE_API_KEY"
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
	// MACSampleSize is how many conn docs the L2 probe samples when
	// estimating MAC field coverage.
	MACSampleSize = 1000
)

// Output handling (DEFILADE_PLAN.md §14): topology artifacts are sensitive.
const (
	OutputDirMode  = 0o700
	OutputFileMode = 0o600
	DataDirName    = "defilade-data"
)

// Scan defaults.
const (
	DefaultWindow       = 14 * 24 * time.Hour // §11 scan --window default
	CompositePageSize   = 1000                // §6.1 composite agg page size
	DefaultMaxEdges     = 500_000             // §6.1 --max-edges safety limit
	ResponderTermsSize  = 2000                // role-evidence responder terms cap
	TopNTemporal        = 50                  // §6.1 second-pass temporal for top-N nodes
	ExactBetweennessMax = 2000                // §10 gonum exact ≤2k nodes
)

// Map generation (DEFILADE_PLAN.md §8).
const (
	GroupPrefixV4         = 24   // §8.2 default subnet grouping prefix
	SparseGroupMinHosts   = 2    // groups below this collapse into "sparse"
	GatewayMACMinIPs      = 10   // §8.4 K: MAC answering for ≥K IPs = gateway
	MapMinConns           = 5    // §8.5 noise floor default
	ClientAggMaxComposite = 0.15 // §8.5 clients below this composite aggregate
	MapTargetElements     = 60   // §8.5 readability target
	MapMaxElements        = 120  // above this, warn to use --focus
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

// Temporal classification thresholds (DEFILADE_PLAN.md §9).
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

// Role inference thresholds (DEFILADE_PLAN.md §7). Every magic number here.
const (
	RoleDCMinKerberosClients = 5
	RoleDNSMinClients        = 5
	RoleFileMinClients       = 3
	RoleDBMinClients         = 2
	RoleWebMinClients        = 5
	RoleJumpMaxInDegree      = 3
	RoleJumpMinOutDegree     = 5
)

// Scoring weights (DEFILADE_PLAN.md §10). Sum ≈ 1.0.
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
	88: ClassAuth, 389: ClassAuth, 636: ClassAuth, 464: ClassAuth,
	53:  ClassName,
	445: ClassFile, 139: ClassFile,
	1433: ClassDB, 3306: ClassDB, 5432: ClassDB, 1521: ClassDB,
	80: ClassWeb, 443: ClassWeb, 8080: ClassWeb, 8443: ClassWeb,
	3389: ClassAdmin, 22: ClassAdmin,
}

// ClassForPort returns the service class of a responder port.
func ClassForPort(port uint16) ServiceClass { return portClass[port] }

// ServiceName returns a short human label for a responder port.
func ServiceName(port uint16) string {
	switch port {
	case 88:
		return "kerberos"
	case 389:
		return "ldap"
	case 636:
		return "ldaps"
	case 464:
		return "kpasswd"
	case 53:
		return "dns"
	case 445:
		return "smb"
	case 139:
		return "netbios"
	case 1433:
		return "mssql"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 1521:
		return "oracle"
	case 80:
		return "http"
	case 443:
		return "https"
	case 3389:
		return "rdp"
	case 22:
		return "ssh"
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
