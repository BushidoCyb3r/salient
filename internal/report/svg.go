package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
)

// SVG renders the briefing map server-side: subnet group boxes, tiered rows
// inside each box (core/service/client), bundled colored edges, legend, and
// hatched blind-spot boxes. Deliberately boring and deterministic — same
// input, same bytes — so it is golden-file testable and drops straight into
// a slide (§8.1).
//
// ponytail: grid layout, no overlap avoidance for edge paths. Upgrade path is
// orthogonal routing, which is what GraphML→draw.io/yEd import is for.
const (
	svgNodeW, svgNodeH = 150, 44
	svgGapX, svgGapY   = 26, 30
	svgGroupPad        = 22
	svgGroupGap        = 40
	svgHeader          = 78
	svgLegendH         = 60
	svgMargin          = 24
	svgMaxRowWidth     = 1400 // groups wrap to a new row past this width — a slide-sized canvas, not an endless ribbon
)

type svgNode struct {
	mapview.MapNode
	x, y float64 // top-left
}

func SVGMap(w io.Writer, m *mapview.Model) error {
	// --- layout ---
	nodesByGroup := map[string][]mapview.MapNode{}
	var floating []mapview.MapNode // observed L2 gateways have no group
	for _, n := range m.Nodes {
		if n.Group == "" {
			floating = append(floating, n)
			continue
		}
		nodesByGroup[n.Group] = append(nodesByGroup[n.Group], n)
	}

	pos := map[string]svgNode{}
	rowTop := float64(svgHeader + svgMargin)
	if len(floating) > 0 {
		rowTop += svgNodeH + float64(svgGapY)
	}
	x := float64(svgMargin)
	rowH := 0.0
	maxWidth := float64(svgMargin)
	type groupBox struct {
		g          mapview.Group
		x, y, w, h float64
	}
	var boxes []groupBox
	maxBottom := rowTop

	for _, g := range m.Groups {
		nodes := nodesByGroup[g.ID]
		// three tier rows inside the box, deterministic order
		tiers := [3][]mapview.MapNode{}
		for _, n := range nodes {
			switch n.Tier {
			case mapview.TierCore:
				tiers[0] = append(tiers[0], n)
			case mapview.TierService:
				tiers[1] = append(tiers[1], n)
			default:
				tiers[2] = append(tiers[2], n)
			}
		}
		cols := 1
		rows := 0
		for _, t := range tiers {
			sort.Slice(t, func(i, j int) bool { return t[i].ID < t[j].ID })
			if len(t) > cols {
				cols = len(t)
			}
			if len(t) > 0 {
				rows++
			}
		}
		if rows == 0 {
			rows = 1 // empty (blind-spot) box still gets a body
		}
		bw := float64(cols)*(svgNodeW+svgGapX) - svgGapX + 2*svgGroupPad
		bh := float64(rows)*(svgNodeH+svgGapY) - svgGapY + 2*svgGroupPad + 20

		// Wrap to a new row once the row-width budget is exceeded — a
		// broad-scope overview has many groups; an endless single-row
		// ribbon is unreadable on a screen or a slide.
		if x+bw > svgMaxRowWidth && x > svgMargin {
			x = svgMargin
			rowTop += rowH + svgGroupGap
			rowH = 0
		}

		row := 0
		for _, t := range tiers {
			if len(t) == 0 {
				continue
			}
			for i, n := range t {
				pos[n.ID] = svgNode{
					MapNode: n,
					x:       x + svgGroupPad + float64(i)*(svgNodeW+svgGapX),
					y:       rowTop + 20 + svgGroupPad + float64(row)*(svgNodeH+svgGapY),
				}
			}
			row++
		}
		boxes = append(boxes, groupBox{g: g, x: x, y: rowTop, w: bw, h: bh})
		if rowTop+bh > maxBottom {
			maxBottom = rowTop + bh
		}
		if bh > rowH {
			rowH = bh
		}
		x += bw + svgGroupGap
		if x > maxWidth {
			maxWidth = x
		}
	}
	for i, n := range floating {
		pos[n.ID] = svgNode{MapNode: n, x: float64(svgMargin) + float64(i)*(svgNodeW+svgGapX), y: float64(svgHeader + svgMargin)}
	}
	width := maxWidth
	if width < 900 {
		width = 900
	}
	height := maxBottom + svgLegendH + 2*svgMargin

	// --- emit ---
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" font-family="system-ui,sans-serif">`+"\n", width, height, width, height)
	b.WriteString(`<defs><pattern id="hatch" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse"><rect width="8" height="8" fill="#f6e8e8"/><line x1="0" y1="0" x2="0" y2="8" stroke="#c96a6a" stroke-width="2"/></pattern></defs>` + "\n")
	b.WriteString(`<rect width="100%" height="100%" fill="#fcfcfd"/>` + "\n")
	fmt.Fprintf(&b, `<text x="%d" y="34" font-size="20" font-weight="700" fill="#1c2330">Defilade briefing map — %s</text>`+"\n", svgMargin, xmlEsc(m.Meta.ClusterName))
	fmt.Fprintf(&b, `<text x="%d" y="56" font-size="12" fill="#6a7180">window %s · generated %s · L3 logical dependency map from observed traffic — not physical topology</text>`+"\n",
		svgMargin, xmlEsc(m.Meta.Window), m.Meta.CreatedAt.Format("2006-01-02 15:04Z"))

	// edges under nodes
	center := func(n svgNode) (float64, float64) { return n.x + svgNodeW/2, n.y + svgNodeH/2 }
	for _, e := range m.Edges {
		s, okS := pos[e.Src]
		d, okD := pos[e.Dst]
		if !okS || !okD {
			continue
		}
		x1, y1 := center(s)
		x2, y2 := center(d)
		fmt.Fprintf(&b, `<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" stroke="%s" stroke-width="%.1f" opacity="0.75"/>`+"\n", x1, y1, x2, y2, e.Color, e.Width)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="10" fill="#555c68" text-anchor="middle">%s</text>`+"\n", (x1+x2)/2, (y1+y2)/2-4, xmlEsc(e.Label))
	}

	// group boxes
	for _, gb := range boxes {
		fill, stroke, dash := "#f2f4f8", "#b9c0cc", ""
		if gb.g.BlindSpot {
			fill, stroke, dash = "url(#hatch)", "#c96a6a", ` stroke-dasharray="6,4"`
		}
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="10" fill="%s" fill-opacity="0.55" stroke="%s"%s/>`+"\n", gb.x, gb.y, gb.w, gb.h, fill, stroke, dash)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="13" font-weight="600" fill="#39414f">%s</text>`+"\n", gb.x+10, gb.y+16, xmlEsc(gb.g.Label))
	}

	// nodes over boxes (drawn after so they sit on top)
	ordered := make([]svgNode, 0, len(pos))
	for _, n := range pos {
		ordered = append(ordered, n)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, n := range ordered {
		fill, stroke, dash := "#ffffff", "#8f97a5", ""
		switch n.Tier {
		case mapview.TierCore:
			fill, stroke = "#fdeee6", "#d95f30"
		case mapview.TierService:
			fill, stroke = "#eaf1fb", "#3d7edb"
		}
		if n.Gateway && n.Inferred {
			dash = ` stroke-dasharray="5,4"`
		}
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.0f" width="%d" height="%d" rx="7" fill="%s" stroke="%s" stroke-width="1.6"%s/>`+"\n", n.x, n.y, svgNodeW, svgNodeH, fill, stroke, dash)
		label := strings.Split(n.Label, "\n")[0]
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="12" font-weight="600" fill="#1c2330" text-anchor="middle">%s</text>`+"\n", n.x+svgNodeW/2, n.y+18, xmlEsc(label))
		sub := n.Role
		if n.Rank > 0 && n.Rank <= 10 {
			sub = fmt.Sprintf("#%d · %s", n.Rank, n.Role)
		}
		if n.AggCount > 0 {
			sub = "aggregated clients"
		}
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="10" fill="#6a7180" text-anchor="middle">%s</text>`+"\n", n.x+svgNodeW/2, n.y+34, xmlEsc(sub))
	}

	// legend
	ly := maxBottom + svgMargin + 18
	fmt.Fprintf(&b, `<text x="%d" y="%.0f" font-size="12" font-weight="600" fill="#39414f">Legend:</text>`+"\n", svgMargin, ly)
	lx := float64(svgMargin + 64)
	for _, item := range legendItems() {
		fmt.Fprintf(&b, `<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" stroke="%s" stroke-width="4"/>`+"\n", lx, ly-4, lx+26, ly-4, item.Color)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="11" fill="#555c68">%s</text>`+"\n", lx+32, ly, xmlEsc(item.Label))
		lx += float64(46 + 8*len(item.Label))
	}
	fmt.Fprintf(&b, `<text x="%d" y="%.0f" font-size="11" fill="#555c68">dashed node = inferred gateway · hatched box = possible sensor blind spot · handle at network classification</text>`+"\n", svgMargin, ly+22)

	b.WriteString("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

type legendItem struct{ Label, Color string }

// legendItems renders the fixed §8.5 palette from config — one source of truth.
func legendItems() []legendItem {
	classes := []config.ServiceClass{
		config.ClassAuth, config.ClassName, config.ClassFile,
		config.ClassDB, config.ClassWeb, config.ClassAdmin, config.ClassOther,
	}
	out := make([]legendItem, 0, len(classes))
	for _, c := range classes {
		out = append(out, legendItem{Label: config.ClassLabel(c), Color: config.MapPalette[c]})
	}
	return out
}

func xmlEsc(s string) string { return esc(s) }
