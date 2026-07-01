package graph

import "testing"

func TestClassifyTemporal(t *testing.T) {
	var sparse, constant, business, nightly, burst [24]int64
	var flatDow, weekdayDow, burstDow [7]int64

	sparse[10] = 5
	for i := range constant {
		constant[i] = 100
	}
	for i := 8; i < 18; i++ {
		business[i] = 100
	}
	nightly[2], nightly[14] = 1000, 50
	burst[14], burst[3] = 1000, 50

	for i := range flatDow {
		flatDow[i] = 150
	}
	for i := 1; i <= 5; i++ {
		weekdayDow[i] = 200
	}
	burstDow[2] = 1050

	cases := []struct {
		name string
		h    [24]int64
		d    [7]int64
		want TemporalClass
	}{
		{"sparse", sparse, flatDow, TemporalSparse},
		{"constant", constant, flatDow, TemporalConstant},
		{"business", business, weekdayDow, TemporalBusinessHours},
		{"nightly", nightly, flatDow, TemporalNightly},
		{"burst", burst, burstDow, TemporalBurst},
	}
	for _, c := range cases {
		if got := ClassifyTemporal(c.h, c.d); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
