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

func TestParseWireGuardLink_URLEncodedAndUserReported(t *testing.T) {
	link := "wireguard://KNWhFayxBFdFwiqeUZPXP3UatGznky3DnC0UNmRDZHE%3D@tgc8337mar.adidasm10.ir:51860/?publickey=uTQ0YkFiu6G7WdLlwcyyFOw7Nyv4KQLdvrhQIm7Cl2Q%3D&address=100.80.2.138%2F32&allowedips=0.0.0.0%2F0%2C%3A%3A%2F0&dns=1.1.1.1%2C1.0.0.1#WGTorkey"

	cfg, err := ParseWireGuardLink(link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Name != "WGTorkey" {
		t.Errorf("expected name 'WGTorkey', got '%s'", cfg.Name)
	}
	if cfg.PrivateKey != "KNWhFayxBFdFwiqeUZPXP3UatGznky3DnC0UNmRDZHE=" {
		t.Errorf("expected private key 'KNWhFayxBFdFwiqeUZPXP3UatGznky3DnC0UNmRDZHE=', got '%s'", cfg.PrivateKey)
	}
	if cfg.PublicKey != "uTQ0YkFiu6G7WdLlwcyyFOw7Nyv4KQLdvrhQIm7Cl2Q=" {
		t.Errorf("expected public key 'uTQ0YkFiu6G7WdLlwcyyFOw7Nyv4KQLdvrhQIm7Cl2Q=', got '%s'", cfg.PublicKey)
	}
	if cfg.Endpoint != "tgc8337mar.adidasm10.ir:51860" {
		t.Errorf("expected endpoint 'tgc8337mar.adidasm10.ir:51860', got '%s'", cfg.Endpoint)
	}
	if cfg.Address != "100.80.2.138/32" {
		t.Errorf("expected address '100.80.2.138/32', got '%s'", cfg.Address)
	}
	if cfg.DNS != "1.1.1.1,1.0.0.1" {
		t.Errorf("expected dns '1.1.1.1,1.0.0.1', got '%s'", cfg.DNS)
	}
	if cfg.AllowedIPs != "0.0.0.0/0,::/0" {
		t.Errorf("expected allowedips '0.0.0.0/0,::/0', got '%s'", cfg.AllowedIPs)
	}
}

func TestParseWireGuardLink_SpecialCharsInBase64Keys(t *testing.T) {
	// Tests + and / inside keys
	link := "wireguard://abc+123/xyz=@host.domain:51820?publickey=pub+key/123=&presharedkey=psk+key/456="

	cfg, err := ParseWireGuardLink(link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.PrivateKey != "abc+123/xyz=" {
		t.Errorf("expected private key 'abc+123/xyz=', got '%s'", cfg.PrivateKey)
	}
	if cfg.PublicKey != "pub+key/123=" {
		t.Errorf("expected public key 'pub+key/123=', got '%s'", cfg.PublicKey)
	}
	if cfg.PresharedKey != "psk+key/456=" {
		t.Errorf("expected preshared key 'psk+key/456=', got '%s'", cfg.PresharedKey)
	}
}

func TestParseBatchLinks(t *testing.T) {
	content := `
# Example batch file with comments
wireguard://key1=@1.1.1.1:51820?publickey=pub1#Server1

// Another comment
wireguard://key2=@2.2.2.2:51820?publickey=pub2#Server2
wg://key3=@3.3.3.3:51820?publickey=pub3#Server3

invalid_link_to_ignore
`

	configs, errs := ParseBatchLinks(content)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(configs) != 3 {
		t.Fatalf("expected 3 configs, got %d", len(configs))
	}
	if configs[0].Name != "Server1" || configs[1].Name != "Server2" || configs[2].Name != "Server3" {
		t.Errorf("config names mismatch: %s, %s, %s", configs[0].Name, configs[1].Name, configs[2].Name)
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
