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

// cleanBase64Key ensures that spaces produced by query decoding are converted back to '+'.
// Base64 WireGuard keys never contain spaces.
func cleanBase64Key(key string) string {
	key = strings.TrimSpace(key)
	return strings.ReplaceAll(key, " ", "+")
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

	// Remainder after scheme://
	remainder := rawLink[len(scheme)+3:]

	// Extract Fragment (#name)
	var fragment string
	if idx := strings.Index(remainder, "#"); idx != -1 {
		fragment = remainder[idx+1:]
		remainder = remainder[:idx]
		if unescaped, err := url.QueryUnescape(fragment); err == nil {
			fragment = unescaped
		}
		fragment = strings.TrimSpace(fragment)
	}

	// Extract Query (?params)
	var queryString string
	if idx := strings.Index(remainder, "?"); idx != -1 {
		queryString = remainder[idx+1:]
		remainder = remainder[:idx]
	}

	params, err := url.ParseQuery(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query parameters: %w", err)
	}

	// Remainder now contains authority: [userinfo@]endpoint[/]
	authority := strings.TrimPrefix(remainder, "/")
	authority = strings.TrimSuffix(authority, "/")

	var privateKey string
	var endpoint string

	if idx := strings.LastIndex(authority, "@"); idx != -1 {
		rawUserinfo := authority[:idx]
		endpoint = authority[idx+1:]

		// Decode userinfo for privateKey
		if unescaped, err := url.QueryUnescape(rawUserinfo); err == nil {
			privateKey = cleanBase64Key(unescaped)
		} else {
			privateKey = cleanBase64Key(rawUserinfo)
		}
	} else {
		endpoint = authority
	}

	// Clean trailing slashes from endpoint
	endpoint = strings.Trim(endpoint, "/")

	// If privateKey was not in userinfo, check query params
	if privateKey == "" {
		privateKey = cleanBase64Key(getFirstParam(params, "privatekey", "private_key", "privkey"))
	}

	// If endpoint was not in authority, check query params
	if endpoint == "" {
		endpoint = getFirstParam(params, "endpoint", "host")
		endpoint = strings.Trim(endpoint, "/")
	}

	// Extract Public Key
	publicKey := cleanBase64Key(getFirstParam(params, "publickey", "public_key", "pubkey"))

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

	// Extract DNS (default to 1.1.1.1 if not provided)
	dns := getFirstParam(params, "dns")
	if dns == "" {
		dns = "1.1.1.1"
	}

	// Extract AllowedIPs (default to all traffic)
	allowedIPs := getFirstParam(params, "allowed_ips", "allowedips")
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}

	// Extract MTU: Only set if explicitly provided in query!
	mtu := getFirstParam(params, "mtu")

	// Extract PresharedKey (optional)
	presharedKey := getFirstParam(params, "presharedkey", "preshared_key", "psk")
	if presharedKey != "" {
		presharedKey = cleanBase64Key(presharedKey)
	}

	// Extract PersistentKeepalive (optional)
	persistentKeepalive := getFirstParam(params, "persistent_keepalive", "persistentkeepalive", "keepalive")

	return &Config{
		Name:                fragment,
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

// ParseBatchLinks parses multiple WireGuard links from text (e.g. from a file),
// ignoring empty lines and comments.
func ParseBatchLinks(content string) ([]*Config, []error) {
	lines := strings.Split(content, "\n")
	var configs []*Config
	var errs []error

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.Trim(trimmed, `"'`)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "wireguard://") && !strings.HasPrefix(lower, "wg://") {
			continue
		}

		cfg, err := ParseWireGuardLink(trimmed)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
		} else {
			configs = append(configs, cfg)
		}
	}

	return configs, errs
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
