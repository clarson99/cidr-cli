package cidr

import (
	"net"
	"testing"
)

func TestGenerateTable(t *testing.T) {
	rows := GenerateTable()
	if len(rows) != 33 {
		t.Fatalf("expected 33 rows, got %d", len(rows))
	}
	// Check known values
	tests := []struct {
		prefix  int
		count   uint64
		netmask string
	}{
		{0, 4294967296, "0.0.0.0"},
		{8, 16777216, "255.0.0.0"},
		{16, 65536, "255.255.0.0"},
		{24, 256, "255.255.255.0"},
		{32, 1, "255.255.255.255"},
	}
	for _, tt := range tests {
		row := rows[tt.prefix]
		if row.IPCount != tt.count {
			t.Errorf("prefix /%d: expected IPCount %d, got %d", tt.prefix, tt.count, row.IPCount)
		}
		if row.Netmask != tt.netmask {
			t.Errorf("prefix /%d: expected netmask %s, got %s", tt.prefix, tt.netmask, row.Netmask)
		}
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		ip    string
		cidr  string
		want  bool
		err   bool
	}{
		{"192.168.1.1", "192.168.1.0/24", true, false},
		{"192.168.2.1", "192.168.1.0/24", false, false},
		{"10.0.0.1", "10.0.0.0/8", true, false},
		{"11.0.0.1", "10.0.0.0/8", false, false},
		{"invalid", "10.0.0.0/8", false, true},
		{"10.0.0.1", "bad-cidr", false, true},
	}
	for _, tt := range tests {
		got, err := Contains(tt.ip, tt.cidr)
		if (err != nil) != tt.err {
			t.Errorf("Contains(%q, %q) error = %v, want error=%v", tt.ip, tt.cidr, err, tt.err)
		}
		if err == nil && got != tt.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
		}
	}
}

func TestNetworkInfo(t *testing.T) {
	info, err := NetworkInfo("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.PrefixLength != 24 {
		t.Errorf("expected prefix 24, got %d", info.PrefixLength)
	}
	if info.TotalHosts != 256 {
		t.Errorf("expected 256 total hosts, got %d", info.TotalHosts)
	}
	if info.UsableHosts != 254 {
		t.Errorf("expected 254 usable hosts, got %d", info.UsableHosts)
	}
	if !info.Network.Equal(net.ParseIP("192.168.1.0")) {
		t.Errorf("expected network 192.168.1.0, got %s", info.Network)
	}
	if !info.Broadcast.Equal(net.ParseIP("192.168.1.255")) {
		t.Errorf("expected broadcast 192.168.1.255, got %s", info.Broadcast)
	}
	if info.Netmask != "255.255.255.0" {
		t.Errorf("expected netmask 255.255.255.0, got %s", info.Netmask)
	}
}

func TestNetworkInfoSlash31(t *testing.T) {
	info, err := NetworkInfo("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	if info.UsableHosts != 2 {
		t.Errorf("expected 2 usable hosts for /31, got %d", info.UsableHosts)
	}
}

func TestNetworkInfoSlash32(t *testing.T) {
	info, err := NetworkInfo("10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if info.UsableHosts != 1 {
		t.Errorf("expected 1 usable host for /32, got %d", info.UsableHosts)
	}
}

func TestNetworkInfoNoPrefix(t *testing.T) {
	info, err := NetworkInfo("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if info.PrefixLength != 32 {
		t.Errorf("expected prefix 32 for bare IP, got %d", info.PrefixLength)
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{1, "1"},
		{256, "256"},
		{65536, "65,536"},
		{16777216, "16,777,216"},
		{4294967296, "4,294,967,296"},
	}
	for _, tt := range tests {
		got := FormatCount(tt.n)
		if got != tt.want {
			t.Errorf("FormatCount(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestClassForPrefix(t *testing.T) {
	tests := []struct {
		prefix int
		want   string
	}{
		{0, "A"},
		{7, "A"},
		{8, "B"},
		{15, "B"},
		{16, "C"},
		{23, "C"},
		{24, "D/E"},
		{31, "D/E"},
		{32, ""},
	}
	for _, tt := range tests {
		got := classForPrefix(tt.prefix)
		if got != tt.want {
			t.Errorf("classForPrefix(%d) = %q, want %q", tt.prefix, got, tt.want)
		}
	}
}
