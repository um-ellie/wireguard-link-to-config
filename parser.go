package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Config represents a WireGuard client configuration.
type Config struct {
	Name                string
	PrivateKey          string
	Address             string
	DNS                 string
	MTU                 string // Empty if not specified
	PublicKey           string
	Endpoint            string
	AllowedIPs          string
	PresharedKey        string // Optional
	PersistentKeepalive string // Optional
}

// SanitizeConfigName cleans and validates a configuration name.
func SanitizeConfigName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if strings.HasSuffix(strings.ToLower(name), ".conf") {
		name = name[:len(name)-5]
	}
	name = strings.TrimSpace(name)

	if name == "" {
		return "", errors.New("configuration name cannot be empty")
	}
	if strings.ContainsAny(name, "/\\:*?\"<>|") || name == "." || name == ".." {
		return "", fmt.Errorf("invalid characters in configuration name: '%s'", name)
	}

	return name, nil
}

// getFirstParam returns the first non-empty value found for any of the given keys in url.Values.
func getFirstParam(v url.Values, keys ...string) string {
	for _, k := range keys {
		if val := strings.TrimSpace(v.Get(k)); val != "" {
			return val
		}
	}
	return ""
}

// ParseWireGuardLink parses a WireGuard URI into a Config struct.
// Supports both 'wireguard://' and 'wg://' schemes.
func ParseWireGuardLink(rawLink string) (*Config, error) {
	rawLink = strings.TrimSpace(rawLink)
	// Remove outer single/double quotes if user wrapped the URL in them
	rawLink = strings.Trim(rawLink, `"'`)

	if rawLink == "" {
		return nil, errors.New("empty link provided")
	}

	var scheme string
	lower := strings.ToLower(rawLink)
	if strings.HasPrefix(lower, "wireguard://") {
		scheme = "wireguard"
	} else if strings.HasPrefix(lower, "wg://") {
		scheme = "wg"
	} else {
		return nil, errors.New("invalid scheme: link must start with 'wireguard://' or 'wg://'")
	}

	// Workaround for Go's net/url parsing when scheme is custom:
	// Replace custom scheme with https:// temporarily for robust parsing of userinfo, host, query, fragment
	normalized := "https://" + rawLink[len(scheme)+3:]

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to parse link: %w", err)
	}

	params := parsed.Query()

	// Extract Private Key (from userinfo or query parameters)
	var privateKey string
	if parsed.User != nil {
		privateKey = parsed.User.Username()
	}
	if privateKey == "" {
		privateKey = getFirstParam(params, "privatekey", "private_key", "privkey")
	}
	privateKey, _ = url.QueryUnescape(privateKey)

	// Extract Endpoint (from host:port or query parameter)
	endpoint := parsed.Host
	if endpoint == "" {
		endpoint = getFirstParam(params, "endpoint", "host")
	}
	endpoint, _ = url.QueryUnescape(endpoint)

	// Extract Public Key
	publicKey := getFirstParam(params, "publickey", "public_key", "pubkey")
	publicKey, _ = url.QueryUnescape(publicKey)

	// Validate essential fields
	if privateKey == "" {
		return nil, errors.New("missing required field: PrivateKey (not found in userinfo or query)")
	}
	if publicKey == "" {
		return nil, errors.New("missing required field: PublicKey")
	}
	if endpoint == "" {
		return nil, errors.New("missing required field: Endpoint")
	}

	// Extract Address (default to 10.0.0.2/32 if not provided)
	address := getFirstParam(params, "address", "ip")
	if address == "" {
		address = "10.0.0.2/32"
	}
	address, _ = url.QueryUnescape(address)

	// Extract DNS (default to 1.1.1.1 if not provided)
	dns := getFirstParam(params, "dns")
	if dns == "" {
		dns = "1.1.1.1"
	}
	dns, _ = url.QueryUnescape(dns)

	// Extract AllowedIPs (default to all traffic)
	allowedIPs := getFirstParam(params, "allowed_ips", "allowedips")
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}
	allowedIPs, _ = url.QueryUnescape(allowedIPs)

	// Extract MTU: Only set if explicitly provided in query!
	mtu := getFirstParam(params, "mtu")

	// Extract PresharedKey (optional)
	presharedKey := getFirstParam(params, "presharedkey", "preshared_key", "psk")
	if presharedKey != "" {
		presharedKey, _ = url.QueryUnescape(presharedKey)
	}

	// Extract PersistentKeepalive (optional)
	persistentKeepalive := getFirstParam(params, "persistent_keepalive", "persistentkeepalive", "keepalive")

	// Extract Name from fragment (e.g. #Germany or #MyServer)
	name := parsed.Fragment
	if name != "" {
		if unescaped, err := url.QueryUnescape(name); err == nil {
			name = unescaped
		}
	}

	return &Config{
		Name:                name,
		PrivateKey:          privateKey,
		Address:             address,
		DNS:                 dns,
		MTU:                 mtu,
		PublicKey:           publicKey,
		Endpoint:            endpoint,
		AllowedIPs:          allowedIPs,
		PresharedKey:        presharedKey,
		PersistentKeepalive: persistentKeepalive,
	}, nil
}

// ToConf formats the Config into standard WireGuard INI configuration.
func (c *Config) ToConf() string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey))
	b.WriteString(fmt.Sprintf("Address = %s\n", c.Address))
	if c.DNS != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", c.DNS))
	}
	if c.MTU != "" {
		b.WriteString(fmt.Sprintf("MTU = %s\n", c.MTU))
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", c.PublicKey))
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", c.Endpoint))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", c.AllowedIPs))

	if c.PresharedKey != "" {
		b.WriteString(fmt.Sprintf("PresharedKey = %s\n", c.PresharedKey))
	}
	if c.PersistentKeepalive != "" {
		b.WriteString(fmt.Sprintf("PersistentKeepalive = %s\n", c.PersistentKeepalive))
	}

	return b.String()
}
