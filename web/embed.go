// Package web embeds the JS libraries for the interactive briefing map.
// Everything ships inside the binary — no CDN, no network (§1 constraint).
package web

import _ "embed"

//go:embed cytoscape.min.js
var Cytoscape []byte

//go:embed layout-base.js
var LayoutBase []byte

//go:embed cose-base.js
var CoseBase []byte

//go:embed cytoscape-fcose.js
var Fcose []byte

//go:embed dagre.min.js
var Dagre []byte

//go:embed cytoscape-dagre.js
var CytoscapeDagre []byte
