// Package cidr provides CIDR calculation utilities.
package cidr

import (
	"fmt"
	"math"
	"net"
	"strings"
)

// TableRow represents one row in the CIDR prefix reference table.
type TableRow struct {
	Prefix   int
	IPCount  uint64
	Class    string // Legacy class (A, B, C, D, E) or ""
	Netmask  string // Dotted-decimal netmask
	Wildcard string // Wildcard (inverted netmask)
}

// GenerateTable returns a row for each prefix length 0–32.
func GenerateTable() []TableRow {
	rows := make([]TableRow, 33)
	for i := 0; i <= 32; i++ {
		count := uint64(math.Pow(2, float64(64-i))) // use uint64 safe path
		if i <= 32 {
			count = uint64(1) << (32 - i)
		}
		rows[i] = TableRow{
			Prefix:   i,
			IPCount:  count,
			Class:    classForPrefix(i),
			Netmask:  netmaskForPrefix(i),
			Wildcard: wildcardForPrefix(i),
		}
	}
	return rows
}

func classForPrefix(prefix int) string {
	switch {
	case prefix <= 7:
		return "A"
	case prefix <= 15:
		return "B"
	case prefix <= 23:
		return "C"
	case prefix <= 31:
		return "D/E"
	default:
		return ""
	}
}

func netmaskForPrefix(ones int) string {
	mask := net.CIDRMask(ones, 32)
	return formatMask(mask)
}

func wildcardForPrefix(ones int) string {
	mask := net.CIDRMask(ones, 32)
	wc := make(net.IPMask, len(mask))
	for i, b := range mask {
		wc[i] = ^b
	}
	return formatMask(wc)
}

func formatMask(m net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

// Contains reports whether ipStr is within the CIDR network cidrStr.
func Contains(ipStr, cidrStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s: %w", cidrStr, err)
	}
	return network.Contains(ip), nil
}

// Info holds parsed details about a CIDR block.
type Info struct {
	CIDR         string
	Network      net.IP
	Mask         net.IPMask
	Ones         int
	Bits         int
	PrefixLength int
	TotalHosts   uint64
	UsableHosts  uint64
	FirstHost    net.IP
	LastHost     net.IP
	Broadcast    net.IP
	Netmask      string
	Wildcard     string
	Class        string
}

// NetworkInfo parses a CIDR string and returns detailed information.
func NetworkInfo(cidrStr string) (*Info, error) {
	if !strings.Contains(cidrStr, "/") {
		cidrStr = cidrStr + "/32"
	}

	ip, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s: %w", cidrStr, err)
	}

	ones, bits := network.Mask.Size()
	total := uint64(1) << (bits - ones)

	// Network address
	networkAddr := network.IP

	// Broadcast address
	broadcast := make(net.IP, len(networkAddr))
	copy(broadcast, networkAddr)
	for i := range broadcast {
		broadcast[i] |= ^network.Mask[i]
	}

	// First and last usable hosts
	var firstHost, lastHost net.IP
	var usable uint64
	if ones < bits-1 {
		// More than 2 hosts: subtract network and broadcast
		firstHost = make(net.IP, len(networkAddr))
		copy(firstHost, networkAddr)
		lastHost = make(net.IP, len(broadcast))
		copy(lastHost, broadcast)
		// Increment last octet of network for first host
		for j := len(firstHost) - 1; j >= 0; j-- {
			firstHost[j]++
			if firstHost[j] != 0 {
				break
			}
		}
		// Decrement last octet of broadcast for last host
		for j := len(lastHost) - 1; j >= 0; j-- {
			lastHost[j]--
			if lastHost[j] != 255 {
				break
			}
		}
		usable = total - 2
	} else if ones == bits-1 {
		// /31: 2 hosts, both usable (RFC 3021)
		firstHost = make(net.IP, len(networkAddr))
		copy(firstHost, networkAddr)
		lastHost = make(net.IP, len(broadcast))
		copy(lastHost, broadcast)
		usable = total
	} else {
		// /32: 1 host
		firstHost = make(net.IP, len(networkAddr))
		copy(firstHost, networkAddr)
		lastHost = make(net.IP, len(broadcast))
		copy(lastHost, broadcast)
		usable = total
	}

	_ = ip // parsed IP is the host address, useful for display
	return &Info{
		CIDR:         cidrStr,
		Network:      networkAddr,
		Mask:         network.Mask,
		Ones:         ones,
		Bits:         bits,
		PrefixLength: ones,
		TotalHosts:   total,
		UsableHosts:  usable,
		FirstHost:    firstHost,
		LastHost:     lastHost,
		Broadcast:    broadcast,
		Netmask:      netmaskForPrefix(ones),
		Wildcard:     wildcardForPrefix(ones),
		Class:        classForPrefix(ones),
	}, nil
}

// FormatCount formats an IP count with commas.
func FormatCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	// Insert commas every 3 digits from the right
	if len(s) <= 3 {
		return s
	}
	var parts []string
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}
