// Package graph holds Salient's core data model and the pipeline that turns
// observed edges into a scored, role-typed dependency graph. It is the single
// source of truth: a Snapshot is what gets persisted; every report and map is
// a pure function of a Snapshot.
package graph

import (
	"net/netip"
	"time"
)

// TerrainAddr reports whether an IP can be terrain: a rankable, mappable
// host. Multicast, broadcast, unspecified, loopback, and link-local addresses
// are traffic artifacts (DHCP, mDNS, IGMP, cloud metadata 169.254.169.254),
// not hosts, no matter how much traffic converges on them.
// ponytail: only the all-ones broadcast is caught; subnet-directed
// broadcasts (x.x.x.255) need the subnet mask, add if they show up ranked.
func TerrainAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return !a.IsMulticast() && !a.IsUnspecified() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && ip != "255.255.255.255"
}

// Role is an inferred host function (SALIENT_PLAN.md §7). Gateway is
// synthesized later by the mapview package (Phase 1.5), not here.
type Role string

const (
	RoleDC          Role = "DomainController"
	RoleDNS         Role = "DNSServer"
	RoleFileServer  Role = "FileServer"
	RoleDatabase    Role = "Database"
	RoleJumpBox     Role = "JumpBox"
	RoleWebServer   Role = "WebServer"
	RolePrinter     Role = "Printer"
	RoleCamera      Role = "Camera"
	RoleMail        Role = "MailServer"
	RoleNetworkGear Role = "NetworkGear"
	RoleUnknown     Role = "Unknown"
)

// RoleAssertion is one inferred role with the evidence that justifies it. A
// rank without a defensible "why" is useless on a mission, so every assertion
// carries human-readable evidence strings.
type RoleAssertion struct {
	Role       Role     `json:"role"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// TemporalClass is the cheap-heuristic activity shape of an edge (§9).
type TemporalClass string

const (
	TemporalUnknown       TemporalClass = ""
	TemporalConstant      TemporalClass = "Constant"
	TemporalBusinessHours TemporalClass = "BusinessHours"
	TemporalNightly       TemporalClass = "Nightly"
	TemporalSparse        TemporalClass = "Sparse"
	TemporalBurst         TemporalClass = "Burst"
)

// TemporalProfile is populated only for edges touching top-N nodes (§6.1
// second pass); Class is TemporalUnknown otherwise.
type TemporalProfile struct {
	HourHistogram [24]int64     `json:"hour_histogram"`
	DowHistogram  [7]int64      `json:"dow_histogram"`
	Class         TemporalClass `json:"class"`
}

// Edge is a directed dependency: originator (client) Src depends on responder
// (server) Dst, observed on Port. Bytes and timestamps are aggregate over the
// analysis window.
type Edge struct {
	Src       string           `json:"src"`
	Dst       string           `json:"dst"`
	Port      uint16           `json:"port"`
	Service   string           `json:"service"`
	Evidence  EvidenceLevel    `json:"evidence,omitempty"`
	ConnCount int64            `json:"conn_count"`
	BytesOut  int64            `json:"bytes_out"`
	BytesIn   int64            `json:"bytes_in"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
	Sensors   []string         `json:"sensors,omitempty"`
	Temporal  *TemporalProfile `json:"temporal,omitempty"`
}

// ScoreSet is the composite terrain score and its components (§10).
type ScoreSet struct {
	DependencyInDegree int     `json:"dependency_in_degree"`
	PageRank           float64 `json:"pagerank"`
	Betweenness        float64 `json:"betweenness"`
	Composite          float64 `json:"composite"`
	Rank               int     `json:"rank"`
}

// Node is a host and everything inferred about it.
type Node struct {
	IP              string          `json:"ip"`
	Hostnames       []string        `json:"hostnames,omitempty"`
	Roles           []RoleAssertion `json:"roles,omitempty"`
	TerrainEvidence []string        `json:"terrain_evidence,omitempty"`
	Subnet          string          `json:"subnet"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	Sensors         []string        `json:"sensors,omitempty"`
	MAC             string          `json:"mac,omitempty"` // responder MAC (own NIC; gateway MACs excluded)
	Scores          ScoreSet        `json:"scores"`
}

// TopRole returns the highest-confidence role label for display, or
// RoleUnknown when nothing was inferred. Roles are stored confidence-sorted
// by InferRoles.
func (n Node) TopRole() Role {
	if len(n.Roles) == 0 {
		return RoleUnknown
	}
	return n.Roles[0].Role
}

// RoleEvidence is the per-responder client-cardinality result of one
// role-evidence query (§6.2). Produced by escli, consumed by inference.
type RoleEvidence struct {
	Clients     int64    // distinct client IPs observed to this responder
	SampleHosts []string // a few example client IPs, for evidence strings
}

// L2Gateway is MAC-convergence evidence gathered at scan time (§8.4 primary):
// a responder MAC that answered for many distinct IPs on a sensor's segment.
type L2Gateway struct {
	MAC     string `json:"mac"`
	Sensor  string `json:"sensor,omitempty"`
	IPCount int64  `json:"ip_count"`
}

// SnapshotMeta records how a snapshot was produced.
type SnapshotMeta struct {
	CreatedAt      time.Time   `json:"created_at"`
	Window         string      `json:"window"`
	Scope          []string    `json:"scope"`
	ClusterName    string      `json:"cluster_name"`
	Sensors        []string    `json:"sensors,omitempty"`
	ZeroCovCIDRs   []string    `json:"zero_coverage_cidrs,omitempty"`
	L2Gateways     []L2Gateway `json:"l2_gateways,omitempty"`
	BetweenSampled bool        `json:"betweenness_sampled"`
	Tool           string      `json:"tool"`
}

// Snapshot is the persisted unit and single source of truth.
type Snapshot struct {
	Meta  SnapshotMeta `json:"meta"`
	Nodes []Node       `json:"nodes"`
	Edges []Edge       `json:"edges"`
}
