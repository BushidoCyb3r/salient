// Package config centralizes every tunable threshold and default in
// Defilade. No magic numbers inline anywhere else (DEFILADE_PLAN.md §15).
package config

import "time"

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
