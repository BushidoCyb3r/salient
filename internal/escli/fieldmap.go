// Package escli is Defilade's read-only Elasticsearch access layer.
//
// Every field name and index pattern used in a query lives in FieldMap,
// never as an inline string in query builders. A wrong field name against
// Elasticsearch fails silently (empty aggregation buckets, not errors), so
// a version mismatch must always be fixable with --fieldmap custom.yaml
// rather than a rebuild.
package escli

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FieldMap maps Defilade's abstract field concepts onto the concrete
// ECS/Zeek field names of the target Security Onion deployment.
type FieldMap struct {
	// IndexPattern selects the indices/data streams holding Zeek logs.
	IndexPattern string `yaml:"index_pattern"`
	// Timestamp is the event time field used for window filtering.
	Timestamp string `yaml:"timestamp"`
	// DatasetField discriminates Zeek log types within IndexPattern.
	DatasetField string `yaml:"dataset_field"`
	// ObserverName identifies which sensor recorded the event.
	ObserverName string `yaml:"observer_name"`

	SourceIP         string `yaml:"source_ip"`
	DestinationIP    string `yaml:"destination_ip"`
	DestinationPort  string `yaml:"destination_port"`
	Service          string `yaml:"service"`
	SourceBytes      string `yaml:"source_bytes"`
	DestinationBytes string `yaml:"destination_bytes"`
	SourceMAC        string `yaml:"source_mac"`
	DestinationMAC   string `yaml:"destination_mac"`

	// Datasets holds candidate DatasetField values per Zeek log type.
	// Security Onion releases have shipped both bare ("conn") and
	// prefixed ("zeek.conn") dataset names; `defilade discover` reports
	// which candidates actually exist on the grid so the map can be
	// pinned in a custom fieldmap.
	Datasets DatasetCandidates `yaml:"datasets"`
}

// DatasetCandidates lists possible dataset values per log type, in
// preference order. Empty entries inherit the defaults.
type DatasetCandidates struct {
	Conn     []string `yaml:"conn"`
	DNS      []string `yaml:"dns"`
	Kerberos []string `yaml:"kerberos"`
	SMB      []string `yaml:"smb"`
	SSL      []string `yaml:"ssl"`
	HTTP     []string `yaml:"http"`
	DHCP     []string `yaml:"dhcp"`
	LDAP     []string `yaml:"ldap"`
}

// DefaultFieldMap returns the assumed SO 2.4-era mapping.
//
// UNVERIFIED: every value below is an assumption from DEFILADE_PLAN.md §6.
// Phase 0's exit criterion is replacing these with ground truth observed by
// `defilade discover` against a real grid, recorded in docs/FIELDMAP.md.
func DefaultFieldMap() FieldMap {
	return FieldMap{
		IndexPattern: "logs-*",          // UNVERIFIED
		Timestamp:    "@timestamp",      // UNVERIFIED
		DatasetField: "event.dataset",   // UNVERIFIED
		ObserverName: "observer.name",   // UNVERIFIED
		SourceIP:     "source.ip",       // UNVERIFIED
		DestinationIP:   "destination.ip",   // UNVERIFIED
		DestinationPort: "destination.port", // UNVERIFIED
		Service:         "network.protocol", // UNVERIFIED
		SourceBytes:      "source.bytes",      // UNVERIFIED
		DestinationBytes: "destination.bytes", // UNVERIFIED
		SourceMAC:        "source.mac",        // UNVERIFIED — may not survive ECS mapping
		DestinationMAC:   "destination.mac",   // UNVERIFIED — may not survive ECS mapping
		Datasets: DatasetCandidates{
			Conn:     []string{"conn", "zeek.conn"},
			DNS:      []string{"dns", "zeek.dns"},
			Kerberos: []string{"kerberos", "zeek.kerberos"},
			SMB:      []string{"smb_mapping", "smb_files", "zeek.smb_mapping", "zeek.smb_files"},
			SSL:      []string{"ssl", "zeek.ssl"},
			HTTP:     []string{"http", "zeek.http"},
			DHCP:     []string{"dhcp", "zeek.dhcp"},
			LDAP:     []string{"ldap", "zeek.ldap"},
		},
	}
}

// LoadFieldMap reads a YAML override file and merges it over the defaults:
// any field left empty in the file keeps its default value.
func LoadFieldMap(path string) (FieldMap, error) {
	fm := DefaultFieldMap()
	if path == "" {
		return fm, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fm, fmt.Errorf("reading fieldmap %s: %w", path, err)
	}
	var override FieldMap
	if err := yaml.Unmarshal(raw, &override); err != nil {
		return fm, fmt.Errorf("parsing fieldmap %s: %w", path, err)
	}
	merge(&fm.IndexPattern, override.IndexPattern)
	merge(&fm.Timestamp, override.Timestamp)
	merge(&fm.DatasetField, override.DatasetField)
	merge(&fm.ObserverName, override.ObserverName)
	merge(&fm.SourceIP, override.SourceIP)
	merge(&fm.DestinationIP, override.DestinationIP)
	merge(&fm.DestinationPort, override.DestinationPort)
	merge(&fm.Service, override.Service)
	merge(&fm.SourceBytes, override.SourceBytes)
	merge(&fm.DestinationBytes, override.DestinationBytes)
	merge(&fm.SourceMAC, override.SourceMAC)
	merge(&fm.DestinationMAC, override.DestinationMAC)
	mergeList(&fm.Datasets.Conn, override.Datasets.Conn)
	mergeList(&fm.Datasets.DNS, override.Datasets.DNS)
	mergeList(&fm.Datasets.Kerberos, override.Datasets.Kerberos)
	mergeList(&fm.Datasets.SMB, override.Datasets.SMB)
	mergeList(&fm.Datasets.SSL, override.Datasets.SSL)
	mergeList(&fm.Datasets.HTTP, override.Datasets.HTTP)
	mergeList(&fm.Datasets.DHCP, override.Datasets.DHCP)
	mergeList(&fm.Datasets.LDAP, override.Datasets.LDAP)
	return fm, nil
}

func merge(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func mergeList(dst *[]string, v []string) {
	if len(v) > 0 {
		*dst = v
	}
}

// CoreConnFields returns the fields the sanity probe verifies against the
// conn dataset. Order matters only for display.
func (fm FieldMap) CoreConnFields() []string {
	return []string{
		fm.SourceIP, fm.DestinationIP, fm.DestinationPort,
		fm.Service, fm.SourceBytes, fm.DestinationBytes,
		fm.ObserverName,
	}
}

// L2Fields returns the MAC fields whose presence decides whether gateway
// inference (§8.4) can use its primary method.
func (fm FieldMap) L2Fields() []string {
	return []string{fm.SourceMAC, fm.DestinationMAC}
}
