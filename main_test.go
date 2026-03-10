package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIP4ToU32LE(t *testing.T) {
	got, err := ip4ToU32LE(net.ParseIP("192.168.1.10"))
	if err != nil {
		t.Fatalf("ip4ToU32LE returned error: %v", err)
	}
	if got != 0x0A01A8C0 {
		t.Fatalf("unexpected value: got %#x want %#x", got, uint32(0x0A01A8C0))
	}
}

func TestIP4ToU32LERejectsNonIPv4(t *testing.T) {
	if _, err := ip4ToU32LE(net.ParseIP("2001:db8::1")); err == nil {
		t.Fatal("expected error for non-ipv4 input")
	}
}

func TestIsVersionFlagRequested(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{"baozap", "--version"}
	if !isVersionFlagRequested() {
		t.Fatal("expected --version to be detected")
	}

	os.Args = []string{"baozap", "-v"}
	if !isVersionFlagRequested() {
		t.Fatal("expected -v to be detected")
	}

	os.Args = []string{"baozap"}
	if isVersionFlagRequested() {
		t.Fatal("did not expect version flag to be detected")
	}
}

func TestIsXDPModeUnsupported(t *testing.T) {
	if !isXDPModeUnsupported(unix.EOPNOTSUPP) {
		t.Fatal("expected EOPNOTSUPP to be unsupported")
	}
	if !isXDPModeUnsupported(errors.New("operation not supported")) {
		t.Fatal("expected error text to be unsupported")
	}
	if isXDPModeUnsupported(unix.EPERM) {
		t.Fatal("did not expect EPERM to be unsupported")
	}
}

func TestConfigDebugDefaultsToFalse(t *testing.T) {
	raw := `{"rules":[{"relay_interface":"eth0","target_interface":"eth0","relay_port":9999,"target_ip":"127.0.0.1","target_port":11786}]}`
	var conf Config
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&conf); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if conf.Debug {
		t.Fatal("expected debug default false when field is omitted")
	}
}

func TestConfigRuleModeOverride(t *testing.T) {
	raw := `{
		"mode":"tc",
		"rules":[
			{"mode":"xdp","relay_interface":"eth0","target_interface":"eth0","relay_port":9999,"target_ip":"127.0.0.1","target_port":11786},
			{"relay_interface":"eth1","target_interface":"eth1","relay_port":9998,"target_ip":"127.0.0.1","target_port":11787}
		]
	}`
	var conf Config
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&conf); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if conf.Rules[0].Mode != "xdp" {
		t.Fatalf("first rule mode = %q, want xdp", conf.Rules[0].Mode)
	}
	if conf.Rules[1].Mode != "" {
		t.Fatalf("second rule mode = %q, want empty for top-level fallback", conf.Rules[1].Mode)
	}
}

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		fallback string
		want     string
		wantErr  bool
	}{
		{name: "rule override", mode: "XDP", fallback: "tc", want: "xdp"},
		{name: "top level fallback", mode: "", fallback: "xdp", want: "xdp"},
		{name: "default tc", mode: "", fallback: "", want: "tc"},
		{name: "invalid", mode: "foo", fallback: "tc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMode(tt.mode, tt.fallback)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMode returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMergeAttachMode(t *testing.T) {
	plans := map[int]*attachPlan{}

	mergeAttachMode(plans, 2, "eth0", "tc")
	mergeAttachMode(plans, 2, "eth0", "xdp")
	mergeAttachMode(plans, 3, "eth1", "xdp")

	if got := plans[2]; got == nil || !got.tc || !got.xdp || got.ifName != "eth0" {
		t.Fatalf("plans[2] = %#v, want tc+xdp on eth0", got)
	}
	if got := plans[3]; got == nil || got.tc || !got.xdp || got.ifName != "eth1" {
		t.Fatalf("plans[3] = %#v, want xdp only on eth1", got)
	}
}
