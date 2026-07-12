package escli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultFieldMapComplete(t *testing.T) {
	fm := DefaultFieldMap()
	for name, v := range map[string]string{
		"IndexPattern": fm.IndexPattern, "Timestamp": fm.Timestamp,
		"DatasetField": fm.DatasetField, "ObserverName": fm.ObserverName,
		"MessageField": fm.MessageField, "SSLServerName": fm.SSLServerName,
		"SSHHostKey": fm.SSHHostKey,
		"SourceIP":   fm.SourceIP, "DestinationIP": fm.DestinationIP,
		"DestinationPort": fm.DestinationPort, "Service": fm.Service,
		"SourceBytes": fm.SourceBytes, "DestinationBytes": fm.DestinationBytes,
		"SourceMAC": fm.SourceMAC, "DestinationMAC": fm.DestinationMAC,
	} {
		if v == "" {
			t.Errorf("default FieldMap.%s is empty", name)
		}
	}
	if len(fm.Datasets.Conn) == 0 {
		t.Error("default FieldMap has no conn dataset candidates")
	}
}

func TestLoadFieldMapNoPathReturnsDefaults(t *testing.T) {
	fm, err := LoadFieldMap("")
	if err != nil {
		t.Fatal(err)
	}
	if fm.SourceIP != DefaultFieldMap().SourceIP {
		t.Errorf("expected defaults, got SourceIP=%q", fm.SourceIP)
	}
}

func TestLoadFieldMapOverrideMergesOverDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fm.yaml")
	yaml := "index_pattern: \"so-zeek-*\"\nmessage_field: zeek_message\nssl_server_name: tls.server.name\nssh_host_key: ssh.server.key\nsource_mac: \"zeek.conn.orig_l2_addr\"\ndatasets:\n  conn: [\"zeek.conn\"]\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	fm, err := LoadFieldMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if fm.IndexPattern != "so-zeek-*" {
		t.Errorf("override not applied: IndexPattern=%q", fm.IndexPattern)
	}
	if fm.SourceMAC != "zeek.conn.orig_l2_addr" {
		t.Errorf("override not applied: SourceMAC=%q", fm.SourceMAC)
	}
	if fm.MessageField != "zeek_message" || fm.SSLServerName != "tls.server.name" || fm.SSHHostKey != "ssh.server.key" {
		t.Errorf("identity overrides not applied: %+v", fm)
	}
	if len(fm.Datasets.Conn) != 1 || fm.Datasets.Conn[0] != "zeek.conn" {
		t.Errorf("dataset override not applied: %v", fm.Datasets.Conn)
	}
	// Untouched fields keep defaults.
	if fm.SourceIP != "source.ip" {
		t.Errorf("default lost during merge: SourceIP=%q", fm.SourceIP)
	}
	if len(fm.Datasets.DNS) == 0 {
		t.Error("default DNS candidates lost during merge")
	}
}

func TestLoadFieldMapMissingFile(t *testing.T) {
	if _, err := LoadFieldMap("/nonexistent/fm.yaml"); err == nil {
		t.Fatal("expected error for missing fieldmap file")
	}
}

func TestFieldMapConnState(t *testing.T) {
	fm := DefaultFieldMap()
	if fm.ConnState != "connection.state" {
		t.Errorf("default ConnState = %q, want connection.state", fm.ConnState)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fm.yaml")
	if err := os.WriteFile(path, []byte("conn_state: zeek.conn.conn_state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fm, err := LoadFieldMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if fm.ConnState != "zeek.conn.conn_state" {
		t.Errorf("override ConnState = %q", fm.ConnState)
	}
	if fm.SourceIP != "source.ip" {
		t.Errorf("unrelated default clobbered: SourceIP = %q", fm.SourceIP)
	}
}
