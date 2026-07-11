package hunt

import "fmt"

// OQLQuery builds a minimal Security Onion Hunt query string for a lead:
// the responder IP and port, in OQL's ECS-field syntax. Intentionally
// minimal (no embedded time range — Hunt's own date picker handles that;
// pass Lead.FirstSeen/LastSeen to the operator separately) since this has
// no prior art in this codebase and cannot be validated against a real
// grid in this environment. Confirm and extend once Phase 0's live-grid
// validation (docs/superpowers/plans/2026-07-11-service-evidence-tiers.md)
// verifies the target Security Onion version's exact OQL field names.
func OQLQuery(l Lead) string {
	return fmt.Sprintf(`destination.ip:%q AND destination.port:%d`, l.IP, l.Port)
}
