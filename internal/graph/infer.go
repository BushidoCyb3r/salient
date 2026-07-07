package graph

import (
	"fmt"
	"sort"

	"github.com/BushidoCyb3r/salient/internal/config"
)

// Evidence bundles the per-protocol responder->client-cardinality results that
// role inference needs, keyed by responder IP.
type Evidence struct {
	Kerberos map[string]RoleEvidence
	DNS      map[string]RoleEvidence
	SMB      map[string]RoleEvidence
	HTTP     map[string]RoleEvidence
	SSL      map[string]RoleEvidence
	LDAP     map[string]RoleEvidence // presence corroborates DC
}

// InferRoles applies the seven v1 rules (§7) to every node, using the
// protocol evidence plus graph shape derived from edges. Confidence scales
// with evidence cardinality, capped at 1.0. Everything unmatched stays
// Unknown — an honest Unknown beats a wrong guess.
func (m *Model) InferRoles(ev Evidence) {
	shape := m.adminShape()
	dbClients := m.clientCounts(func(p uint16) bool { return config.ClassForPort(p) == config.ClassDB })
	printerClients := m.clientCounts(func(p uint16) bool { return p == 631 || p == 9100 })
	cameraClients := m.clientCounts(func(p uint16) bool { return p == 554 })
	mailClients := m.clientCounts(isMailPort)
	gearClients := m.clientCounts(config.IsNetworkGearPort)

	for ip, n := range m.Nodes {
		var roles []RoleAssertion

		// DomainController: ≥N kerberos clients AND ldap observed here.
		if k, ok := ev.Kerberos[ip]; ok && k.Clients >= config.RoleDCMinKerberosClients {
			if _, ldap := ev.LDAP[ip]; ldap {
				roles = append(roles, assert(RoleDC, k.Clients, config.RoleDCMinKerberosClients,
					fmt.Sprintf("%d distinct hosts made Kerberos requests to this host; LDAP also observed", k.Clients)))
			}
		}
		// DNSServer.
		if d, ok := ev.DNS[ip]; ok && d.Clients >= config.RoleDNSMinClients {
			roles = append(roles, assert(RoleDNS, d.Clients, config.RoleDNSMinClients,
				fmt.Sprintf("%d distinct hosts issued DNS queries to this host", d.Clients)))
		}
		// FileServer.
		if s, ok := ev.SMB[ip]; ok && s.Clients >= config.RoleFileMinClients {
			roles = append(roles, assert(RoleFileServer, s.Clients, config.RoleFileMinClients,
				fmt.Sprintf("%d distinct hosts opened SMB sessions to this host", s.Clients)))
		}
		// Database: DB-port responder with ≥N clients. Temporal class (§9)
		// boosts confidence when a second pass has run, but is not required
		// for the assertion (evidence noted when present).
		if c := dbClients[ip]; c >= config.RoleDBMinClients {
			msg := fmt.Sprintf("%d distinct hosts connected on a database port", c)
			if tc := m.dbTemporal(ip); tc == TemporalConstant || tc == TemporalBusinessHours {
				msg += fmt.Sprintf(" (%s activity)", tc)
			}
			roles = append(roles, assert(RoleDatabase, int64(c), config.RoleDBMinClients, msg))
		}
		// WebServer: http or ssl responder with ≥N clients (take the larger).
		web := maxClients(ev.HTTP[ip], ev.SSL[ip])
		if web >= config.RoleWebMinClients {
			roles = append(roles, assert(RoleWebServer, web, config.RoleWebMinClients,
				fmt.Sprintf("%d distinct hosts made HTTP/TLS requests to this host", web)))
		}
		// Printer / Camera: single-purpose device protocols are strong
		// signals — one observed client suffices.
		if c := printerClients[ip]; c >= config.RolePrinterMinClients {
			roles = append(roles, assert(RolePrinter, int64(c), config.RolePrinterMinClients,
				fmt.Sprintf("%d distinct hosts sent print traffic (ipp/jetdirect) to this host", c)))
		}
		if c := cameraClients[ip]; c >= config.RoleCameraMinClients {
			roles = append(roles, assert(RoleCamera, int64(c), config.RoleCameraMinClients,
				fmt.Sprintf("%d distinct hosts pulled RTSP streams from this host", c)))
		}
		// MailServer: smtp/imap/pop3 responder with ≥N clients.
		if c := mailClients[ip]; c >= config.RoleMailMinClients {
			roles = append(roles, assert(RoleMail, int64(c), config.RoleMailMinClients,
				fmt.Sprintf("%d distinct hosts connected on mail ports (smtp/imap/pop3)", c)))
		}
		// NetworkGear: controller/switch/AP-only protocols (capwap, papi,
		// smart-install, tacacs) — endpoints never serve these.
		if c := gearClients[ip]; c >= config.RoleNetworkGearMinClients {
			roles = append(roles, assert(RoleNetworkGear, int64(c), config.RoleNetworkGearMinClients,
				fmt.Sprintf("%d host(s) used network-infrastructure protocols (capwap/papi/tacacs/smart-install) to this host", c)))
		}
		// JumpBox: few admin sessions in, many out (graph shape).
		if sh, ok := shape[ip]; ok && sh.inDeg <= config.RoleJumpMaxInDegree && sh.outDeg >= config.RoleJumpMinOutDegree {
			roles = append(roles, RoleAssertion{
				Role: RoleJumpBox, Confidence: 0.8,
				Evidence: []string{fmt.Sprintf("RDP/SSH from %d host(s) in, out to %d host(s) — pivot shape", sh.inDeg, sh.outDeg)},
			})
		}

		if len(roles) == 0 {
			roles = []RoleAssertion{{Role: RoleUnknown, Confidence: 0}}
		}
		sort.Slice(roles, func(i, j int) bool { return roles[i].Confidence > roles[j].Confidence })
		n.Roles = roles
	}
}

func assert(r Role, have int64, min int, evidence string) RoleAssertion {
	// Linear confidence from threshold to 5× threshold, capped at 1.0.
	conf := float64(have) / float64(min*5)
	if conf > 1 {
		conf = 1
	}
	if conf < 0.5 {
		conf = 0.5 // met the threshold at all → at least 0.5
	}
	return RoleAssertion{Role: r, Confidence: conf, Evidence: []string{evidence}}
}

func maxClients(a, b RoleEvidence) int64 {
	if a.Clients > b.Clients {
		return a.Clients
	}
	return b.Clients
}

type degree struct{ inDeg, outDeg int }

// adminShape counts distinct RDP/SSH peers in and out per node.
func (m *Model) adminShape() map[string]degree {
	in := map[string]map[string]bool{}
	out := map[string]map[string]bool{}
	for _, e := range m.Edges {
		if !config.IsAdminPort(e.Port) {
			continue
		}
		if in[e.Dst] == nil {
			in[e.Dst] = map[string]bool{}
		}
		in[e.Dst][e.Src] = true
		if out[e.Src] == nil {
			out[e.Src] = map[string]bool{}
		}
		out[e.Src][e.Dst] = true
	}
	res := map[string]degree{}
	for ip := range m.Nodes {
		res[ip] = degree{inDeg: len(in[ip]), outDeg: len(out[ip])}
	}
	return res
}

// clientCounts returns the distinct client count per responder whose port
// matches — the shared cardinality primitive behind port-driven role rules.
func (m *Model) clientCounts(match func(uint16) bool) map[string]int {
	clients := map[string]map[string]bool{}
	for _, e := range m.Edges {
		if !match(e.Port) {
			continue
		}
		if clients[e.Dst] == nil {
			clients[e.Dst] = map[string]bool{}
		}
		clients[e.Dst][e.Src] = true
	}
	out := map[string]int{}
	for ip, set := range clients {
		out[ip] = len(set)
	}
	return out
}

// isMailPort reports smtp/submission/imap/pop3 responder ports.
func isMailPort(p uint16) bool {
	switch p {
	case 25, 465, 587, 110, 995, 143, 993:
		return true
	}
	return false
}

// dbTemporal returns the dominant temporal class of DB-port edges into a node,
// if any second-pass profile is attached.
func (m *Model) dbTemporal(ip string) TemporalClass {
	for _, e := range m.Edges {
		if e.Dst == ip && config.ClassForPort(e.Port) == config.ClassDB && e.Temporal != nil {
			return e.Temporal.Class
		}
	}
	return TemporalUnknown
}
