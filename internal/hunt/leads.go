// internal/hunt/leads.go

// Package hunt composes already-computed Service Authority, drift, and
// reconciliation data into a single deterministic, prioritized list of
// investigation leads. Never produces a rogue/maliciousness probability —
// ordering is an explicit multi-key sort over named facts (reason priority,
// evidence strength, client count, subnet spread, terrain rank).
package hunt

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/netconfig"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// Reason names why a provider surfaced as a lead. Never a probability —
// a fixed, named category the operator can reason about directly.
type Reason string

const (
	ReasonPolicyDenied Reason = "policy-denied" // observed flow a declared device's config denies
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
	case ReasonPolicyDenied, ReasonContradicted:
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
	// Query is the Security Onion Hunt query for this lead — see OQLQuery,
	// the single source; callers must not re-derive it.
	Query string `json:"query"`
	// RuleEvidence names the declared deny rule this responder's traffic
	// violated: "<device> <config-file>:<line> — <raw rule>", plus a
	// "(confidence: partial)" suffix when the device had caveated rules the
	// diff couldn't evaluate. A named fact quoting the operator's own config,
	// never a severity or probability.
	RuleEvidence string `json:"rule_evidence,omitempty"`
	// AlternateProviders lists other observed providers of the same service
	// that share at least one client with this one — evidence of possible
	// failover capacity. Empty means no alternate provider was observed;
	// passive traffic cannot prove a configured failover doesn't exist, so
	// this is worded as an absence of evidence, never "no redundancy."
	AlternateProviders []string `json:"alternate_providers,omitempty"`
}

const sampleClientCap = 5

// providerKey identifies one (responder, port) provider — shared by
// enrichProviders and BuildLeads so their maps key identically.
type providerKey struct {
	ip   string
	port uint16
}

// ProviderKey builds the "ip:port" string key used for operator-approval
// lookups (devices.Registry.ApprovedProviders) — the single canonical
// format, so callers never hand-format it inconsistently.
func ProviderKey(ip string, port uint16) string {
	return fmt.Sprintf("%s:%d", ip, port)
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
// which sensors observed the traffic, and (second return value) the full
// per-provider client set — uncapped, unlike sampleClients — used for
// alternate-provider overlap detection.
func enrichProviders(snap graph.Snapshot) (map[providerKey]providerEnrichment, map[providerKey]map[string]bool) {
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
	return result, seenClient
}

// alternateProviders finds, for each provider, other providers of the same
// service that share at least one client — evidence of possible failover
// capacity. Deterministic: sorted "ip:port" keys, no probability.
func alternateProviders(providers []mapview.ServiceProvider, clients map[providerKey]map[string]bool) map[providerKey][]string {
	byService := map[string][]providerKey{}
	for _, p := range providers {
		byService[p.Service] = append(byService[p.Service], providerKey{p.IP, p.Port})
	}
	out := map[providerKey][]string{}
	for _, keys := range byService {
		for _, p := range keys {
			var alts []string
			for _, q := range keys {
				if q == p {
					continue
				}
				if overlaps(clients[p], clients[q]) {
					alts = append(alts, ProviderKey(q.ip, q.port))
				}
			}
			if alts != nil {
				sort.Strings(alts)
				out[p] = alts
			}
		}
	}
	return out
}

func overlaps(a, b map[string]bool) bool {
	small, big := a, b
	if len(b) < len(a) {
		small, big = b, a
	}
	for c := range small {
		if big[c] {
			return true
		}
	}
	return false
}

// BuildLeads composes current-snapshot providers, drift new-provider
// findings, reconciliation results, and declared-config policy violations
// into a deduplicated, prioritized lead list. diff, rec, and pol are all
// optional (nil skips that source) — a first-ever scan has no baseline to
// diff against, reconciliation requires an operator-supplied asset list, and
// policy diffing requires declared device configs. approved is an optional
// set of "ip:port" keys (see ProviderKey) the operator has already confirmed
// as expected/benign — a matching lead is suppressed entirely, never
// returned. Observed evidence is untouched; suppression is purely a display
// filter.
func BuildLeads(current graph.Snapshot, diff *snapshot.Diff, rec *reconcile.Result, pol *netconfig.PolicyResult, approved map[string]bool) []Lead {
	providers := mapview.BuildServiceAuthority(current)
	enrich, clients := enrichProviders(current)
	alternates := alternateProviders(providers, clients)

	byKey := map[providerKey]*Lead{}
	makeLead := func(p mapview.ServiceProvider) *Lead {
		k := providerKey{p.IP, p.Port}
		e := enrich[k]
		return &Lead{
			IP: p.IP, Hostname: p.Hostname, Service: p.Service, Port: p.Port,
			Evidence: p.Evidence, Clients: p.Clients, Rank: p.Rank,
			FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
			SampleClients: e.sampleClients, Subnets: e.subnets, Sensors: e.sensors,
			AlternateProviders: alternates[k],
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

	if pol != nil {
		// One lead per distinct (responder, port) among violations —
		// responder-centric like every other lead, aggregating the denied
		// flows' sources, service, evidence, and time span.
		type polAgg struct {
			clients   map[string]bool
			sample    []string
			service   string
			evidence  graph.EvidenceLevel
			firstSeen time.Time
			lastSeen  time.Time
			ruleEv    string
		}
		agg := map[providerKey]*polAgg{}
		for _, v := range pol.Violations {
			k := providerKey{v.Edge.Dst, v.Edge.Port}
			a := agg[k]
			if a == nil {
				a = &polAgg{clients: map[string]bool{}, ruleEv: ruleEvidence(v)}
				a.service = v.Edge.Service
				if a.service == "" {
					a.service = config.ServiceName(v.Edge.Port)
				}
				agg[k] = a
			}
			if !a.clients[v.Edge.Src] {
				a.clients[v.Edge.Src] = true
				if len(a.sample) < sampleClientCap {
					a.sample = append(a.sample, v.Edge.Src)
				}
			}
			if evidenceStrength(v.Edge.Evidence) > evidenceStrength(a.evidence) {
				a.evidence = v.Edge.Evidence
			}
			if a.firstSeen.IsZero() || v.Edge.FirstSeen.Before(a.firstSeen) {
				a.firstSeen = v.Edge.FirstSeen
			}
			if v.Edge.LastSeen.After(a.lastSeen) {
				a.lastSeen = v.Edge.LastSeen
			}
		}
		for k, a := range agg {
			// RuleEvidence is a true fact about this responder regardless of
			// which reason wins the tiebreak, so attach it either way.
			if existing, has := byKey[k]; has {
				existing.RuleEvidence = a.ruleEv
				if reasonPriority(ReasonPolicyDenied) < reasonPriority(existing.Reason) {
					existing.Reason = ReasonPolicyDenied
				}
				continue
			}
			byKey[k] = &Lead{
				Reason: ReasonPolicyDenied,
				IP:     k.ip, Port: k.port, Service: a.service,
				Evidence: a.evidence, Clients: len(a.clients),
				SampleClients: a.sample,
				FirstSeen:     a.firstSeen, LastSeen: a.lastSeen,
				RuleEvidence: a.ruleEv,
			}
		}
	}

	leads := make([]Lead, 0, len(byKey))
	for _, l := range byKey {
		if approved[ProviderKey(l.IP, l.Port)] {
			continue
		}
		l.Query = OQLQuery(*l)
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

// ruleEvidence renders a policy violation as the RuleEvidence string: the
// declared device, the config file and line of the deny rule, and the raw
// rule text — plus a partial-confidence note when the device had caveated
// rules the diff couldn't evaluate. Named facts only, no probability.
func ruleEvidence(v netconfig.Violation) string {
	s := fmt.Sprintf("%s %s:%d — %s", v.Device, filepath.Base(v.Source), v.Rule.Line, v.Rule.Raw)
	if v.Confidence == "partial" {
		s += " (confidence: partial)"
	}
	return s
}
