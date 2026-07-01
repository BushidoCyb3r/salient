package graph

import "github.com/BushidoCyb3r/defilade/internal/config"

// ClassifyTemporal applies the §9 cheap heuristics to folded hour-of-day and
// day-of-week histograms (already in the operator's local timezone).
// ponytail: coarse rules by design — Archer's spectral machinery is the v2
// upgrade path, deliberately not imported (§9).
func ClassifyTemporal(hours [24]int64, dow [7]int64) TemporalClass {
	var total int64
	activeHours := 0
	for _, v := range hours {
		total += v
		if v > 0 {
			activeHours++
		}
	}
	if total < config.TemporalSparseMax {
		return TemporalSparse
	}
	dom := float64(total) * config.TemporalDominantFrac

	// Nightly: ≥80% inside some ≤3h window within the night band.
	if bestWindow(hours, config.NightWindowHours, nightHours()) >= int64(dom) {
		return TemporalNightly
	}
	// Burst before BusinessHours: a single-hour spike inside the workday is
	// a burst, not a business rhythm. ≥80% in one hour bucket (~5% of 24).
	var peak int64
	for _, v := range hours {
		if v > peak {
			peak = v
		}
	}
	if float64(peak) >= dom {
		return TemporalBurst
	}
	// BusinessHours: ≥80% 0800–1800 local, weekday-weighted.
	var biz, weekend int64
	for h := config.BusinessStartHour; h < config.BusinessEndHour; h++ {
		biz += hours[h]
	}
	weekend = dow[0] + dow[6] // Sunday, Saturday
	if float64(biz) >= dom && float64(weekend) < float64(total)*(1-config.TemporalDominantFrac) {
		return TemporalBusinessHours
	}
	if activeHours >= config.TemporalConstantHours {
		return TemporalConstant
	}
	return TemporalUnknown
}

// nightHours returns the hour-of-day indices in the night band 2000–0600.
func nightHours() []int {
	var out []int
	for h := config.NightStartHour; h < 24; h++ {
		out = append(out, h)
	}
	for h := 0; h < config.NightEndHour; h++ {
		out = append(out, h)
	}
	return out
}

// bestWindow finds the max volume of any `width` consecutive hours drawn from
// the allowed band (band is circular across midnight).
func bestWindow(hours [24]int64, width int, band []int) int64 {
	var best int64
	for start := 0; start < len(band); start++ {
		var sum int64
		for i := 0; i < width && start+i < len(band); i++ {
			sum += hours[band[start+i]]
		}
		if sum > best {
			best = sum
		}
	}
	return best
}
