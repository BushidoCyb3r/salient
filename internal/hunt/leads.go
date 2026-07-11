// internal/hunt/leads.go

// Package hunt composes already-computed Service Authority, drift, and
// reconciliation data into a single deterministic, prioritized list of
// investigation leads. Never produces a rogue/maliciousness probability —
// ordering is an explicit multi-key sort over named facts (reason priority,
// evidence strength, client count, subnet spread, terrain rank).
package hunt

import (
	"sort"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// Reason names why a provider surfaced as a lead. Never a probability —
// a fixed, named category the operator can reason about directly.
type Reason string

const (
	ReasonContradicted Reason = "contradicted"  // documented role disagrees with what's observed
	ReasonUndocumented Reason = "undocumented"  // provider has no entry in the asset list
	ReasonNewProvider  Reason = "new-provider"  // a brand-new host began providing this service
	ReasonNewService   Reason = "new-service"   // an existing host began providing a new service
	ReasonSoleProvider Reason = "sole-provider" // the only observed provider of this service
)

// reasonPriority orders reasons by actionability: a documented mismatch is
// more actionable than an informational sole-provider note. Lower sorts
// first. Also used to pick the single reason for a provider surfacing under
// more than one condition — the lead is never duplicated, only upgraded.
func reasonPriority(r Reason) int {
	switch r {
	case ReasonContradicted:
		return 0
	case ReasonUndocumented:
		return 1
	case ReasonNewProvider, ReasonNewService:
		return 2
	default: // ReasonSoleProvider
		return 3
	}
}

func evidenceStrength(e graph.EvidenceLevel) int {
	switch e {
	case graph.EvidenceProtocolConfirmed:
		return 2
	case graph.EvidenceResponderConfirmed:
		return 1
	default:
		return 0
	}
}

// Lead is one investigation lead: a service provider surfaced for a
// specific, named reason. Every field is descriptive evidence — never a
// severity, risk, or maliciousness score.
type Lead struct {
	Reason          Reason              `json:"reason"`
	IP              string              `json:"ip"`
	Hostname        string              `json:"hostname,omitempty"`
	Service         string              `json:"service"`
	Port            uint16              `json:"port"`
	Evidence        graph.EvidenceLevel `json:"evidence"`
	Clients         int                 `json:"clients"`
	SampleClients   []string            `json:"sample_clients,omitempty"`
	Subnets         []string            `json:"subnets,omitempty"`
	Sensors         []string            `json:"sensors,omitempty"`
	FirstSeen       time.Time           `json:"first_seen"`
	LastSeen        time.Time           `json:"last_seen"`
	Rank            int                 `json:"rank,omitempty"`
	InventoryStatus string              `json:"inventory_status,omitempty"`
}

const sampleClientCap = 5

// providerKey identifies one (responder, port) provider — shared by
// enrichProviders and BuildLeads so their maps key identically.
type providerKey struct {
	ip   string
	port uint16
}

// providerEnrichment holds the per-(ip,port) facts BuildServiceAuthority
// doesn't retain (it only keeps a count): sample client IPs, distinct
// client subnets, and observing sensors.
type providerEnrichment struct {
	sampleClients []string
	subnets       []string
	sensors       []string
}

// enrichProviders re-scans confirmed sensitive-service edges to collect the
// per-provider facts mapview.ServiceProvider's Clients count alone can't
// give a lead: a few example client IPs, the distinct subnets they're in,
// and which sensors observed the traffic.
func enrichProviders(snap graph.Snapshot) map[providerKey]providerEnrichment {
	nodes := make(map[string]graph.Node, len(snap.Nodes))
	for _, n := range snap.Nodes {
		nodes[n.IP] = n
	}
	seenClient := map[providerKey]map[string]bool{}
	seenSubnet := map[providerKey]map[string]bool{}
	seenSensor := map[providerKey]map[string]bool{}
	out := map[providerKey]*providerEnrichment{}
	for _, e := range snap.Edges {
		if !config.IsSensitiveServicePort(e.Port) || !e.Confirmed() || !graph.TerrainAddr(e.Dst) {
			continue
		}
		k := providerKey{e.Dst, e.Port}
		if _, ok := out[k]; !ok {
			out[k] = &providerEnrichment{}
			seenClient[k] = map[string]bool{}
			seenSubnet[k] = map[string]bool{}
			seenSensor[k] = map[string]bool{}
		}
		if !seenClient[k][e.Src] {
			seenClient[k][e.Src] = true
			if len(out[k].sampleClients) < sampleClientCap {
				out[k].sampleClients = append(out[k].sampleClients, e.Src)
			}
			if sub := nodes[e.Src].Subnet; sub != "" && !seenSubnet[k][sub] {
				seenSubnet[k][sub] = true
				out[k].subnets = append(out[k].subnets, sub)
			}
		}
		for _, s := range e.Sensors {
			if !seenSensor[k][s] {
				seenSensor[k][s] = true
				out[k].sensors = append(out[k].sensors, s)
			}
		}
	}
	result := make(map[providerKey]providerEnrichment, len(out))
	for k, v := range out {
		sort.Strings(v.subnets)
		sort.Strings(v.sensors)
		result[k] = *v
	}
	return result
}

// BuildLeads composes current-snapshot providers, drift new-provider
// findings, and reconciliation results into a deduplicated, prioritized
// lead list. diff and rec are both optional (nil skips that source) — a
// first-ever scan has no baseline to diff against, and reconciliation
// requires an operator-supplied asset list.
func BuildLeads(current graph.Snapshot, diff *snapshot.Diff, rec *reconcile.Result) []Lead {
	providers := mapview.BuildServiceAuthority(current)
	enrich := enrichProviders(current)

	byKey := map[providerKey]*Lead{}
	makeLead := func(p mapview.ServiceProvider) *Lead {
		e := enrich[providerKey{p.IP, p.Port}]
		return &Lead{
			IP: p.IP, Hostname: p.Hostname, Service: p.Service, Port: p.Port,
			Evidence: p.Evidence, Clients: p.Clients, Rank: p.Rank,
			FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
			SampleClients: e.sampleClients, Subnets: e.subnets, Sensors: e.sensors,
		}
	}
	providerByKey := make(map[providerKey]mapview.ServiceProvider, len(providers))
	for _, p := range providers {
		providerByKey[providerKey{p.IP, p.Port}] = p
	}
	upsert := func(ip string, port uint16, reason Reason, invStatus string) {
		k := providerKey{ip, port}
		p, ok := providerByKey[k]
		if !ok {
			return // not a current provider (e.g. vanished since baseline) — nothing to lead on
		}
		existing, has := byKey[k]
		if !has {
			l := makeLead(p)
			l.Reason, l.InventoryStatus = reason, invStatus
			byKey[k] = l
			return
		}
		if reasonPriority(reason) < reasonPriority(existing.Reason) {
			existing.Reason = reason
			if invStatus != "" {
				existing.InventoryStatus = invStatus
			}
		}
	}

	// Sole provider: exactly one provider row for a service in this snapshot.
	byService := map[string][]mapview.ServiceProvider{}
	for _, p := range providers {
		byService[p.Service] = append(byService[p.Service], p)
	}
	for _, rows := range byService {
		if len(rows) == 1 {
			upsert(rows[0].IP, rows[0].Port, ReasonSoleProvider, "")
		}
	}

	if diff != nil {
		for _, np := range diff.NewProviders {
			reason := ReasonNewService
			if np.NewHost {
				reason = ReasonNewProvider
			}
			upsert(np.IP, np.Port, reason, "")
		}
	}

	if rec != nil {
		providerPorts := map[string][]uint16{}
		for _, p := range providers {
			providerPorts[p.IP] = append(providerPorts[p.IP], p.Port)
		}
		for _, n := range rec.ObservedUndocumented {
			for _, port := range providerPorts[n.IP] {
				upsert(n.IP, port, ReasonUndocumented, "undocumented")
			}
		}
		for _, c := range rec.RoleContradicted {
			for _, port := range providerPorts[c.IP] {
				upsert(c.IP, port, ReasonContradicted, "contradicted")
			}
		}
	}

	leads := make([]Lead, 0, len(byKey))
	for _, l := range byKey {
		leads = append(leads, *l)
	}
	sort.Slice(leads, func(i, j int) bool {
		a, b := leads[i], leads[j]
		if reasonPriority(a.Reason) != reasonPriority(b.Reason) {
			return reasonPriority(a.Reason) < reasonPriority(b.Reason)
		}
		if es, fs := evidenceStrength(a.Evidence), evidenceStrength(b.Evidence); es != fs {
			return es > fs
		}
		if a.Clients != b.Clients {
			return a.Clients > b.Clients
		}
		if len(a.Subnets) != len(b.Subnets) {
			return len(a.Subnets) > len(b.Subnets)
		}
		ar, br := a.Rank, b.Rank
		if ar == 0 {
			ar = 1 << 30
		}
		if br == 0 {
			br = 1 << 30
		}
		if ar != br {
			return ar < br
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Port < b.Port
	})
	return leads
}
