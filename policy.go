// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package acme

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// IdentifierPolicy specifies which DNS names or IP addresses the ACME server is
// allowed to issue certificates for. Returning a non-nil error rejects the
// identifier. When no IdentifierPolicy is configured on a [Server], any
// syntactically valid DNS name or public IP address is allowed.
type IdentifierPolicy func(ctx context.Context, id Identifier) error

// ParseAllowIdentifiers parses and validates the given allowlist patterns and
// returns an [IdentifierPolicy] that allows only the specified DNS names,
// wildcard DNS patterns (e.g. "*.example.com"), IP addresses, or CIDR ranges
// (e.g. "192.0.2.0/24" or "2001:db8::/32"). It returns an error if no patterns
// are provided or if any pattern is syntactically invalid.
func ParseAllowIdentifiers(patterns ...string) (IdentifierPolicy, error) {
	var dnsPatterns []string
	var ipAddrs []netip.Addr
	var ipPrefixes []netip.Prefix

	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("acme: empty identifier pattern")
		}
		if strings.Contains(p, "/") {
			prefix, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("acme: invalid CIDR pattern %q: %w", raw, err)
			}
			ipPrefixes = append(ipPrefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(p); err == nil {
			if addr.Zone() != "" {
				return nil, fmt.Errorf("acme: IP pattern %q must not contain a zone", raw)
			}
			ipAddrs = append(ipAddrs, addr.Unmap())
			continue
		}
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(suffix, ".") {
				return nil, fmt.Errorf("acme: wildcard DNS pattern %q must not end with a dot", raw)
			}
			ascii, err := idna.Lookup.ToASCII(suffix)
			if err != nil || !isValidDNSName(ascii) || !strings.Contains(ascii, ".") {
				return nil, fmt.Errorf("acme: invalid wildcard DNS pattern %q", raw)
			}
			dnsPatterns = append(dnsPatterns, "*."+strings.ToLower(ascii))
			continue
		}
		if strings.HasSuffix(p, ".") {
			return nil, fmt.Errorf("acme: DNS pattern %q must not end with a dot", raw)
		}
		ascii, err := idna.Lookup.ToASCII(p)
		if err != nil || !isValidDNSName(ascii) {
			return nil, fmt.Errorf("acme: invalid DNS or IP pattern %q", raw)
		}
		dnsPatterns = append(dnsPatterns, strings.ToLower(ascii))
	}

	if len(dnsPatterns) == 0 && len(ipAddrs) == 0 && len(ipPrefixes) == 0 {
		return nil, fmt.Errorf("acme: at least one identifier pattern is required")
	}

	return buildAllowPolicy(dnsPatterns, ipAddrs, ipPrefixes), nil
}

// AllowIdentifiers returns an [IdentifierPolicy] that allows only the specified
// DNS names, wildcard DNS patterns (e.g. "*.example.com"), IP addresses, or
// CIDR ranges (e.g. "192.0.2.0/24" or "2001:db8::/32"). Invalid or empty
// patterns are ignored; use [ParseAllowIdentifiers] to validate patterns and
// report errors.
func AllowIdentifiers(patterns ...string) IdentifierPolicy {
	var dnsPatterns []string
	var ipAddrs []netip.Addr
	var ipPrefixes []netip.Prefix

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(p); err == nil {
			ipPrefixes = append(ipPrefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(p); err == nil && addr.Zone() == "" {
			ipAddrs = append(ipAddrs, addr.Unmap())
			continue
		}
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(suffix, ".")); err == nil && isValidDNSName(ascii) {
				dnsPatterns = append(dnsPatterns, "*."+strings.ToLower(ascii))
			}
			continue
		}
		if ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(p, ".")); err == nil && isValidDNSName(ascii) {
			dnsPatterns = append(dnsPatterns, strings.ToLower(ascii))
		}
	}

	return buildAllowPolicy(dnsPatterns, ipAddrs, ipPrefixes)
}

func buildAllowPolicy(dnsPatterns []string, ipAddrs []netip.Addr, ipPrefixes []netip.Prefix) IdentifierPolicy {
	return func(_ context.Context, id Identifier) error {
		switch id.Type {
		case IdentifierDNS:
			name := strings.ToLower(strings.TrimSuffix(id.Value, "."))
			for _, pattern := range dnsPatterns {
				if dnsNameMatches(pattern, name) {
					return nil
				}
			}
			return fmt.Errorf("acme: DNS identifier %q is not allowed by policy", id.Value)

		case IdentifierIP:
			addr, err := netip.ParseAddr(id.Value)
			if err != nil {
				return fmt.Errorf("acme: invalid IP identifier %q: %w", id.Value, err)
			}
			addr = addr.Unmap()
			for _, allowed := range ipAddrs {
				if addr == allowed {
					return nil
				}
			}
			for _, prefix := range ipPrefixes {
				if prefix.Contains(addr) {
					return nil
				}
			}
			return fmt.Errorf("acme: IP identifier %q is not allowed by policy", id.Value)

		default:
			return fmt.Errorf("acme: unsupported identifier type %q", id.Type)
		}
	}
}

func dnsNameMatches(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if name == "" {
		return false
	}
	if pattern == name {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*")
	if !ok || !strings.HasPrefix(suffix, ".") {
		return false
	}
	label, ok := strings.CutSuffix(name, suffix)
	return ok && label != "" && !strings.ContainsAny(label, ".*")
}

// normalizeAndValidateIdentifier validates and canonicalizes an ACME identifier.
func normalizeAndValidateIdentifier(id Identifier) (Identifier, *Problem) {
	switch id.Type {
	case IdentifierDNS:
		val := strings.TrimSpace(id.Value)
		if val == "" {
			return Identifier{}, newProblem(http.StatusBadRequest, errMalformed, "empty DNS identifier")
		}
		if strings.HasPrefix(val, "*.") {
			return Identifier{}, newProblem(http.StatusBadRequest, errRejectedIdentifier, "wildcard DNS identifiers are not supported with http-01 or tls-alpn-01")
		}
		if strings.HasSuffix(val, ".") {
			return Identifier{}, newProblem(http.StatusBadRequest, errMalformed, "DNS identifier must not end with a trailing dot")
		}
		if _, err := netip.ParseAddr(val); err == nil {
			return Identifier{}, newProblem(http.StatusBadRequest, errMalformed, "IP address in DNS identifier; use type %q", IdentifierIP)
		}
		ascii, err := idna.Lookup.ToASCII(val)
		if err != nil || !isValidDNSName(ascii) {
			return Identifier{}, newProblem(http.StatusBadRequest, errMalformed, "invalid DNS identifier %q", id.Value)
		}
		return Identifier{
			Type:  IdentifierDNS,
			Value: strings.ToLower(ascii),
		}, nil

	case IdentifierIP:
		val := strings.TrimSpace(id.Value)
		addr, err := netip.ParseAddr(val)
		if err != nil || addr.Zone() != "" {
			return Identifier{}, newProblem(http.StatusBadRequest, errMalformed, "invalid IP identifier %q", id.Value)
		}
		unmapped := addr.Unmap()
		if unmapped.IsUnspecified() || unmapped.IsMulticast() || unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() ||
			(unmapped.Is4() && (unmapped.As4()[0] == 0 || unmapped == netip.MustParseAddr("255.255.255.255"))) {
			return Identifier{}, newProblem(http.StatusBadRequest, errRejectedIdentifier, "restricted IP identifier %q is not allowed", id.Value)
		}
		return Identifier{
			Type:  IdentifierIP,
			Value: unmapped.String(),
		}, nil

	default:
		return Identifier{}, newProblem(http.StatusBadRequest, errUnsupportedIdentifier, "unsupported identifier type %q", id.Type)
	}
}

func isValidDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
