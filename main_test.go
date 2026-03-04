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
