// fakees mimics the exact Elasticsearch surface Defilade touches, plus a
// chat-completions endpoint for `analyze`. Stdlib only. -variant 2 mutates
// the network (new DB server appears, web server vanishes) for drift tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

var variant = flag.Int("variant", 1, "network variant")

type edge struct {
	src, dst string
	port     int
	conns    int
}

func fixtureEdges() []edge {
	var edges []edge
	ws := func(i int) string { return fmt.Sprintf("10.0.3.%d", 30+i) }
	for i := 0; i < 15; i++ {
		edges = append(edges,
			edge{ws(i), "10.0.1.10", 88, 400 + i}, // kerberos -> DC
			edge{ws(i), "10.0.1.11", 53, 900 + i}, // dns
			edge{ws(i), "10.0.1.20", 445, 60 + i}, // smb
		)
	}
	if *variant == 1 {
		for i := 0; i < 8; i++ {
			edges = append(edges, edge{ws(i), "10.0.2.50", 443, 120 + i}) // web
		}
	}
	for i := 0; i < 3; i++ {
		edges = append(edges, edge{ws(i), "10.0.1.30", 5432, 200 + i}) // db
	}
	if *variant == 2 {
		for i := 0; i < 12; i++ {
			edges = append(edges, edge{ws(i), "10.0.1.40", 5432, 500 + i}) // NEW db server
		}
	}
	return edges
}

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address (0.0.0.0 for cross-machine testing, 127.0.0.1 for loopback-only)")
	port := flag.String("port", "9299", "listen port")
	flag.Parse()

	http.HandleFunc("/", route)
	log.Printf("fakees variant %d on %s:%s", *variant, *bind, *port)
	log.Fatal(http.ListenAndServe(*bind+":"+*port, nil))
}

func route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	body, _ := io.ReadAll(r.Body)
	b := string(body)
	switch {
	case r.URL.Path == "/":
		reply(w, `{"cluster_name":"fake-so-grid","version":{"number":"8.14.0"}}`)
	case strings.HasPrefix(r.URL.Path, "/_resolve/index/"):
		reply(w, `{"indices":[{"name":".ds-logs-zeek-000001"}],"data_streams":[{"name":"logs-zeek-so"}],"aliases":[]}`)
	case r.URL.Path == "/_field_caps" || strings.HasSuffix(r.URL.Path, "/_field_caps"):
		fieldCaps(w, r)
	case strings.Contains(r.URL.Path, "_has_privileges"):
		reply(w, `{"has_all_requested":false,"index":{"logs-*":{"write":false,"index":false,"create":false,"create_index":false,"delete":false,"delete_index":false}}}`)
	case r.URL.Path == "/v1/chat/completions":
		llm(w, b)
	case strings.HasSuffix(r.URL.Path, "/_search"):
		search(w, b)
	default:
		log.Printf("UNMOCKED %s %s", r.Method, r.URL.Path)
		http.Error(w, `{"error":"unmocked path"}`, 404)
	}
}

func reply(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, s)
}

func fieldCaps(w http.ResponseWriter, r *http.Request) {
	fields := strings.Split(r.URL.Query().Get("fields"), ",")
	m := map[string]any{}
	for _, f := range fields {
		if f == "" {
			continue
		}
		m[f] = map[string]any{"ip": map[string]any{"type": "ip", "searchable": true, "aggregatable": true}}
	}
	out, _ := json.Marshal(map[string]any{"indices": []string{".ds-logs-zeek-000001"}, "fields": m})
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func search(w http.ResponseWriter, body string) {
	switch {
	case strings.Contains(body, `"edges"`):
		edgesPage(w, body)
	case strings.Contains(body, `"responders"`):
		responders(w, body)
	case strings.Contains(body, `"datasets"`):
		reply(w, wrap(`{"datasets":{"buckets":[
			{"key":"conn","doc_count":100000},{"key":"dns","doc_count":30000},
			{"key":"kerberos","doc_count":8000},{"key":"smb_mapping","doc_count":2000},
			{"key":"ssl","doc_count":15000},{"key":"http","doc_count":5000},
			{"key":"ldap","doc_count":900},{"key":"dhcp","doc_count":400}]}}`))
	case strings.Contains(body, `"sensors"`):
		reply(w, wrap(`{"sensors":{"buckets":[{"key":"so-sensor-1","doc_count":90000},{"key":"so-sensor-2","doc_count":60000}]}}`))
	case strings.Contains(body, `"hist"`):
		hist(w)
	case strings.Contains(body, `"by_sensor"`):
		reply(w, wrap(`{"by_sensor":{"buckets":[{"key":"so-sensor-1","doc_count":90000,
			"macs":{"buckets":[{"key":"aa:bb:cc:dd:ee:01","doc_count":50000,"ips":{"value":25}},
			{"key":"aa:bb:cc:dd:ee:99","doc_count":10,"ips":{"value":2}}]}}]}}`))
	case strings.Contains(body, `"src_mac_present"`):
		reply(w, wrap(`{"src_mac_present":{"doc_count":95000},"dst_mac_present":{"doc_count":94000}}`))
	default:
		log.Printf("UNMOCKED SEARCH BODY: %.200s", body)
		reply(w, wrap(`{}`))
	}
}

func wrap(aggs string) string {
	return `{"took":3,"hits":{"total":{"value":100000}},"aggregations":` + aggs + `}`
}

// edgesPage pages the composite agg in two halves to exercise after_key.
func edgesPage(w http.ResponseWriter, body string) {
	all := fixtureEdges()
	half := len(all) / 2
	page := all[:half]
	after := `,"after_key":{"src":"cursor","dst":"cursor","port":0}`
	if strings.Contains(body, `"after"`) {
		page = all[half:]
		after = ""
	}
	var sb strings.Builder
	for i, e := range page {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"key":{"src":%q,"dst":%q,"port":%d},"doc_count":%d,
			"bytes_out":{"value":%d},"bytes_in":{"value":%d},
			"first":{"value":1780000000000},"last":{"value":1780080000000},
			"sensors":{"buckets":[{"key":"so-sensor-1","doc_count":%d}]}}`,
			e.src, e.dst, e.port, e.conns, e.conns*900, e.conns*4000, e.conns)
	}
	reply(w, wrap(`{"edges":{"buckets":[`+sb.String()+`]`+after+`}}`))
}

func responders(w http.ResponseWriter, body string) {
	bucket := func(ip string, clients int) string {
		return fmt.Sprintf(`{"key":%q,"doc_count":%d,"clients":{"value":%d},
			"sample_hosts":{"buckets":[{"key":"10.0.3.30","doc_count":5},{"key":"10.0.3.31","doc_count":4}]}}`,
			ip, clients*100, clients)
	}
	var buckets []string
	switch {
	case strings.Contains(body, "kerberos"):
		buckets = append(buckets, bucket("10.0.1.10", 15))
	case strings.Contains(body, "ldap"):
		buckets = append(buckets, bucket("10.0.1.10", 15))
	case strings.Contains(body, "dns"):
		buckets = append(buckets, bucket("10.0.1.11", 15))
	case strings.Contains(body, "smb"):
		buckets = append(buckets, bucket("10.0.1.20", 10))
	case strings.Contains(body, "http"):
		if *variant == 1 {
			buckets = append(buckets, bucket("10.0.2.50", 8))
		}
	case strings.Contains(body, "ssl"):
		if *variant == 1 {
			buckets = append(buckets, bucket("10.0.2.50", 8))
		}
	}
	reply(w, wrap(`{"responders":{"buckets":[`+strings.Join(buckets, ",")+`]}}`))
}

// hist returns a business-hours activity shape (0800-1759 UTC weekday-ish).
func hist(w http.ResponseWriter) {
	var sb strings.Builder
	base := int64(1779955200000) // 2026-05-28T00:00:00Z-ish, hour buckets
	for h := 0; h < 72; h++ {
		if h > 0 {
			sb.WriteString(",")
		}
		count := 2
		if hod := h % 24; hod >= 8 && hod < 18 {
			count = 500
		}
		fmt.Fprintf(&sb, `{"key":%d,"doc_count":%d}`, base+int64(h)*3600000, count)
	}
	reply(w, wrap(`{"hist":{"buckets":[`+sb.String()+`]}}`))
}

// llm answers chat-completions with findings citing real fixture IDs.
func llm(w http.ResponseWriter, body string) {
	if !strings.Contains(body, `10.0.1.10`) {
		http.Error(w, "payload missing expected top node", 400)
		return
	}
	content := `{"summary":"DC and DNS are single points of failure.","findings":[` +
		`{"title":"Kerberos hub","severity":"high","rationale":"15 clients depend on one DC.",` +
		`"node_ids":["10.0.1.10"],"edge_ids":[],"confidence":0.9}]}`
	out, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": content}}},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}
