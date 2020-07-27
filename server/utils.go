package server

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// GenerateRamdomBytes from cryptographically secure source
func GenerateRamdomBytes(length int) (value []byte, err error) {
	randomBytes := make([]byte, length)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// AllowedKey contains the allowed values for this key
type AllowedKey struct {
	Index      int
	Key        ssh.PublicKey
	ExpiresAt  time.Time
	Lifetime   time.Duration
	Comment    string
	Principals []string
	Options    map[string]string
	Extensions map[string]string
}

// ParseAuthorizedKeys to []AllowedCertKey format
func ParseAuthorizedKeys(lines []string, defaultLifetime time.Duration) ([]AllowedKey, error) {
	keys := []AllowedKey{}

	// http://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT
	// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

	seenKeys := make(map[string]bool)
	for i, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		publicKey, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("failed to parse line '%s': %v", line, err)
		}

		// Return error if there are duplicates
		strPublicKey := string(ssh.MarshalAuthorizedKey(publicKey))
		if seenKeys[strPublicKey] {
			return nil, fmt.Errorf("public key is listed more than once '%s': %v", line, err)
		}
		seenKeys[strPublicKey] = true

		key := AllowedKey{
			Index:      i,
			Key:        publicKey,
			ExpiresAt:  time.Unix(1<<63-62135596801, 999999999), // MaxTime
			Lifetime:   defaultLifetime,                         // TODO: Add this as option or encode it in the comment field
			Comment:    comment,
			Principals: []string{},
			Options:    map[string]string{},
			Extensions: map[string]string{},
		}

		restricted := false
		disallowedExtensions := []string{""}
		for _, option := range options {
			nameValue := strings.Split(option, "=")
			name := nameValue[0]
			var value string
			if len(nameValue) > 1 {
				value = trimQuotes(nameValue[1])
			}
			switch name {
			case "agent-forwarding":
				key.Extensions["permit-agent-forwarding"] = value
			case "command":
				if value == "" {
					return nil, fmt.Errorf("empty command not allowed")
				}
				key.Options["force-command"] = value
			case "expiry-time":
				expiresAt, err := time.Parse("2006010215040599", value)
				if err != nil {
					return nil, fmt.Errorf("expiry-time not valid format %s", value)
				}
				key.ExpiresAt = expiresAt
			case "from":
				// TODO: Convert wildcard matching to CIDR address/masklen notation
				key.Options["source-address"] = value
			case "no-agent-forwarding":
				disallowedExtensions = append(disallowedExtensions, "permit-agent-forwarding")
			case "no-port-forwarding":
				disallowedExtensions = append(disallowedExtensions, "permit-port-forwarding")
			case "no-pty":
				disallowedExtensions = append(disallowedExtensions, "permit-pty")
			case "no-user-rc":
				disallowedExtensions = append(disallowedExtensions, "permit-user-rc")
			case "no-X11-forwarding":
				disallowedExtensions = append(disallowedExtensions, "permit-X11-forwarding")
			case "port-forwarding":
				key.Extensions["permit-port-forwarding"] = value
			case "principals":
				key.Principals = strings.Split(value, ",")
			case "pty":
				key.Extensions["permit-pty"] = value
			case "no-touch-required":
				key.Extensions["no-presence-required"] = value
			case "restrict":
				restricted = true
			case "user-rc":
				key.Extensions["permit-user-rc"] = value
			case "X11-forwarding":
				key.Extensions["permit-X11-forwarding"] = value
			default:
				return nil, fmt.Errorf("unknown option %s", name)
			}
		}

		// Enable all extensions if they are not restricted
		if !restricted {
			key.Extensions["no-presence-required"] = ""
			key.Extensions["permit-X11-forwarding"] = ""
			key.Extensions["permit-agent-forwarding"] = ""
			key.Extensions["permit-port-forwarding"] = ""
			key.Extensions["permit-pty"] = ""
			key.Extensions["permit-user-rc"] = ""
		}

		// Remove all extentions that have been explicitly forbidden
		for _, extension := range disallowedExtensions {
			delete(key.Extensions, extension)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	}
	return s
}
