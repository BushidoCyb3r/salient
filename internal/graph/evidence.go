// internal/graph/evidence.go
package graph

// EvidenceLevel grades how strongly observed traffic proves that Dst
// actually provided the service on an edge. Port-only edges stay in
// snapshots as hunt context but never influence terrain scoring or role
// inference — a SYN scan must not mint a service provider.
type EvidenceLevel string

const (
	// EvidenceUnknown marks legacy snapshots and unclassifiable edges.
	// Treated as confirmed so pre-existing snapshots keep their scores.
	EvidenceUnknown EvidenceLevel = ""
	// EvidencePortOnly: connection attempts with no observed responder
	// participation (SYN-only, rejected, unanswered).
	EvidencePortOnly EvidenceLevel = "port-only"
	// EvidenceResponderConfirmed: the responder demonstrably took part —
	// an established Zeek conn state or responder payload bytes.
	EvidenceResponderConfirmed EvidenceLevel = "responder-confirmed"
	// EvidenceProtocolConfirmed: Zeek identified the application protocol.
	EvidenceProtocolConfirmed EvidenceLevel = "protocol-confirmed"
)

// respondedStates are Zeek conn_state values where the responder
// participated: normal termination, established variants, and
// established-then-reset. S0/REJ/OTH/SH/SHR/RSTRH/RSTOS0 are not proof.
var respondedStates = map[string]bool{
	"SF": true, "S1": true, "S2": true, "S3": true, "RSTO": true, "RSTR": true,
}

// ClassifyEvidence grades one aggregated edge from its conn_state terms
// histogram, observed application protocols, and responder byte sum. The
// bytesIn fallback keeps grids lacking a conn_state field honest instead
// of degrading everything to port-only.
func ClassifyEvidence(states map[string]int64, protocols []string, bytesIn int64) EvidenceLevel {
	for _, p := range protocols {
		if p != "" && p != "-" && p != "unknown" {
			return EvidenceProtocolConfirmed
		}
	}
	for s, c := range states {
		if c > 0 && respondedStates[s] {
			return EvidenceResponderConfirmed
		}
	}
	if bytesIn > 0 {
		return EvidenceResponderConfirmed
	}
	return EvidencePortOnly
}

// Confirmed reports whether the edge may influence terrain scoring and
// role inference. Only proven port-only is barred; Unknown (legacy) passes.
func (e Edge) Confirmed() bool { return e.Evidence != EvidencePortOnly }
