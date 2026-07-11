package hunt

import "testing"

func TestOQLQuery(t *testing.T) {
	l := Lead{IP: "10.0.1.99", Port: 53}
	got := OQLQuery(l)
	want := `destination.ip:"10.0.1.99" AND destination.port:53`
	if got != want {
		t.Errorf("OQLQuery = %q, want %q", got, want)
	}
}

func TestOQLQueryEmptyIP(t *testing.T) {
	// A Lead should never have an empty IP in practice, but the function
	// must not panic on a zero-value input.
	got := OQLQuery(Lead{})
	if got == "" {
		t.Error("OQLQuery(Lead{}) returned empty string, want a (degenerate but non-empty) query")
	}
}
