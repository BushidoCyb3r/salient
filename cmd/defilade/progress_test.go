package main

import (
	"bytes"
	"testing"
	"time"
)

func TestSpinnerWritesAndClears(t *testing.T) {
	var out bytes.Buffer
	stop := startSpinner(&out, time.Hour)
	stop()

	if got, want := out.String(), "\r|\r \r"; got != want {
		t.Fatalf("spinner output = %q, want %q", got, want)
	}
}
