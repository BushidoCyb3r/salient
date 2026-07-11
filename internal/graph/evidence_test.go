// internal/graph/evidence_test.go
package graph

import "testing"

func TestClassifyEvidence(t *testing.T) {
	cases := []struct {
		name    string
		states  map[string]int64
		protos  []string
		bytesIn int64
		want    EvidenceLevel
	}{
		{"syn scan", map[string]int64{"S0": 40}, nil, 0, EvidencePortOnly},
		{"rejected", map[string]int64{"REJ": 3}, nil, 0, EvidencePortOnly},
		{"established SF", map[string]int64{"SF": 10}, nil, 2000, EvidenceResponderConfirmed},
		{"established then originator reset", map[string]int64{"RSTO": 2}, nil, 0, EvidenceResponderConfirmed},
		{"protocol identified", map[string]int64{"SF": 10}, []string{"dns"}, 500, EvidenceProtocolConfirmed},
		{"protocol placeholder dash ignored", map[string]int64{"S0": 5}, []string{"-"}, 0, EvidencePortOnly},
		{"no state field, responder bytes fallback", nil, nil, 1500, EvidenceResponderConfirmed},
		{"no state field, no bytes", nil, nil, 0, EvidencePortOnly},
		{"midstream OTH with responder bytes", map[string]int64{"OTH": 4}, nil, 900, EvidenceResponderConfirmed},
	}
	for _, c := range cases {
		if got := ClassifyEvidence(c.states, c.protos, c.bytesIn); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestEdgeConfirmed(t *testing.T) {
	if (Edge{Evidence: EvidencePortOnly}).Confirmed() {
		t.Error("port-only edge must not be confirmed")
	}
	// Legacy snapshots have no evidence field; they keep today's behavior.
	if !(Edge{}).Confirmed() {
		t.Error("legacy (unknown) edge must stay confirmed")
	}
	if !(Edge{Evidence: EvidenceResponderConfirmed}).Confirmed() {
		t.Error("responder-confirmed edge must be confirmed")
	}
}
