package main

import (
	"strings"
	"testing"
)

func TestParseWireGuardLink_Standard(t *testing.T) {
	link := "wireguard://cGVyc29uYWxfcHJpdmF0ZV9rZXk=@198.51.100.1:51820?publickey=cGVyc29uYWxfcHVibGljX2tleQ==&address=10.0.0.5/32&dns=8.8.8.8&allowed_ips=0.0.0.0/0#MyServer"

	cfg, err := ParseWireGuardLink(link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Name != "MyServer" {
		t.Errorf("expected name 'MyServer', got '%s'", cfg.Name)
	}
	if cfg.PrivateKey != "cGVyc29uYWxfcHJpdmF0ZV9rZXk=" {
		t.Errorf("expected private key 'cGVyc29uYWxfcHJpdmF0ZV9rZXk=', got '%s'", cfg.PrivateKey)
	}
	if cfg.PublicKey != "cGVyc29uYWxfcHVibGljX2tleQ==" {
		t.Errorf("expected public key 'cGVyc29uYWxfcHVibGljX2tleQ==', got '%s'", cfg.PublicKey)
	}
	if cfg.Endpoint != "198.51.100.1:51820" {
		t.Errorf("expected endpoint '198.51.100.1:51820', got '%s'", cfg.Endpoint)
	}
	if cfg.Address != "10.0.0.5/32" {
		t.Errorf("expected address '10.0.0.5/32', got '%s'", cfg.Address)
	}
	if cfg.DNS != "8.8.8.8" {
		t.Errorf("expected dns '8.8.8.8', got '%s'", cfg.DNS)
	}
	// MTU should be empty since not in link!
	if cfg.MTU != "" {
		t.Errorf("expected empty MTU, got '%s'", cfg.MTU)
	}

	conf := cfg.ToConf()
	if strings.Contains(conf, "MTU =") {
		t.Errorf("conf output should NOT contain MTU when not provided, but got:\n%s", conf)
	}
}

func TestParseWireGuardLink_WithMTUAndKeepalive(t *testing.T) {
	link := "wg://my_priv_key@wg.example.com:51820?publickey=my_pub_key&mtu=1420&keepalive=25&presharedkey=my_psk#Test_Node"

	cfg, err := ParseWireGuardLink(link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Name != "Test_Node" {
		t.Errorf("expected name 'Test_Node', got '%s'", cfg.Name)
	}
	if cfg.MTU != "1420" {
		t.Errorf("expected MTU '1420', got '%s'", cfg.MTU)
	}
	if cfg.PersistentKeepalive != "25" {
		t.Errorf("expected PersistentKeepalive '25', got '%s'", cfg.PersistentKeepalive)
	}
	if cfg.PresharedKey != "my_psk" {
		t.Errorf("expected PresharedKey 'my_psk', got '%s'", cfg.PresharedKey)
	}

	conf := cfg.ToConf()
	if !strings.Contains(conf, "MTU = 1420") {
		t.Errorf("conf output should contain MTU = 1420, got:\n%s", conf)
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("conf output should contain PersistentKeepalive = 25, got:\n%s", conf)
	}
	if !strings.Contains(conf, "PresharedKey = my_psk") {
		t.Errorf("conf output should contain PresharedKey = my_psk, got:\n%s", conf)
	}
}

func TestParseWireGuardLink_MissingRequired(t *testing.T) {
	// Missing publickey
	link := "wireguard://my_priv_key@1.2.3.4:51820"
	_, err := ParseWireGuardLink(link)
	if err == nil {
		t.Errorf("expected error for missing public key, but got nil")
	}

	// Invalid scheme
	linkInvalid := "http://my_priv_key@1.2.3.4:51820?publickey=abc"
	_, err = ParseWireGuardLink(linkInvalid)
	if err == nil {
		t.Errorf("expected error for invalid scheme, but got nil")
	}
}

func TestSanitizeConfigName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasErr   bool
	}{
		{"Germany", "Germany", false},
		{"MyServer.conf", "MyServer", false},
		{"  TORK.CONF  ", "TORK", false},
		{"../evil", "", true},
		{"foo/bar", "", true},
		{"foo\\bar", "", true},
		{".", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		res, err := SanitizeConfigName(tt.input)
		if tt.hasErr && err == nil {
			t.Errorf("SanitizeConfigName(%q) expected error, got nil", tt.input)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("SanitizeConfigName(%q) unexpected error: %v", tt.input, err)
		}
		if res != tt.expected {
			t.Errorf("SanitizeConfigName(%q) = %q; expected %q", tt.input, res, tt.expected)
		}
	}
}
