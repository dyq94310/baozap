//go:build linux && xdp_integration

package baozaptest

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	xdpPass     = 2
	xdpTx       = 3
	tcActOK     = 0
	tcRedirect  = 7
	ipProtoUDP  = 17
	ipProtoICMP = 1
	ethHdrLen   = 14
	ipv4HdrLen  = 20
	udpHdrLen   = 8
	ipv4EthType = 0x0800
	snatMinPort = 49152
	snatMaxPort = 65535
)

type relayObjects struct {
	TcRelayFunc  *ebpf.Program `ebpf:"tc_relay_func"`
	XdpRelayFunc *ebpf.Program `ebpf:"xdp_relay_func"`
	ConfigMap    *ebpf.Map     `ebpf:"config_map"`
}

func (o *relayObjects) Close() error {
	if o.TcRelayFunc != nil {
		_ = o.TcRelayFunc.Close()
	}
	if o.XdpRelayFunc != nil {
		_ = o.XdpRelayFunc.Close()
	}
	if o.ConfigMap != nil {
		_ = o.ConfigMap.Close()
	}
	return nil
}

type udpTuple struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

func TestXDPForwardAndReverseRewrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	relayIP := "10.10.0.1"
	targetIP := "172.16.8.9"
	clientIP := "192.168.50.100"

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	nextHopMAC := [6]byte{0x02, 0xde, 0xad, 0xbe, 0xef, 0x10}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	targetMAC := [6]byte{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}

	const relayPort = uint16(9999)
	const targetPort = uint16(11786)
	const clientPort = uint16(54321)

	if err := writeRelayRule(objs.ConfigMap, relayPort, relayIP, targetIP, targetPort, relayMAC, nextHopMAC, 0, 0); err != nil {
		t.Fatalf("write relay rule: %v", err)
	}

	forwardIn := buildUDPPacket(
		clientMAC,
		relayMAC,
		udpTuple{
			srcIP:   clientIP,
			dstIP:   relayIP,
			srcPort: clientPort,
			dstPort: relayPort,
		},
	)

	ret, forwardOut, err := objs.XdpRelayFunc.Test(forwardIn)
	if err != nil {
		t.Fatalf("xdp forward test: %v", err)
	}
	if ret != xdpTx {
		t.Fatalf("forward action = %d, want XDP_TX(%d)", ret, xdpTx)
	}

	gotDstMAC, gotSrcMAC, gotSrcIP, gotDstIP, gotSrcPort, gotDstPort := decodeUDPPacket(t, forwardOut)
	if !bytes.Equal(gotDstMAC[:], nextHopMAC[:]) {
		t.Fatalf("forward dst mac = %x, want %x", gotDstMAC, nextHopMAC)
	}
	if !bytes.Equal(gotSrcMAC[:], relayMAC[:]) {
		t.Fatalf("forward src mac = %x, want %x", gotSrcMAC, relayMAC)
	}
	if gotSrcIP.String() != relayIP {
		t.Fatalf("forward src ip = %s, want %s", gotSrcIP, relayIP)
	}
	if gotDstIP.String() != targetIP {
		t.Fatalf("forward dst ip = %s, want %s", gotDstIP, targetIP)
	}
	if gotDstPort != targetPort {
		t.Fatalf("forward dst port = %d, want %d", gotDstPort, targetPort)
	}
	if gotSrcPort < snatMinPort || gotSrcPort > snatMaxPort {
		t.Fatalf("snat port out of range: %d", gotSrcPort)
	}

	reverseIn := buildUDPPacket(
		targetMAC,
		relayMAC,
		udpTuple{
			srcIP:   targetIP,
			dstIP:   relayIP,
			srcPort: targetPort,
			dstPort: gotSrcPort, // SNAT port from forward path
		},
	)

	ret, reverseOut, err := objs.XdpRelayFunc.Test(reverseIn)
	if err != nil {
		t.Fatalf("xdp reverse test: %v", err)
	}
	if ret != xdpTx {
		t.Fatalf("reverse action = %d, want XDP_TX(%d)", ret, xdpTx)
	}

	gotDstMAC, gotSrcMAC, gotSrcIP, gotDstIP, gotSrcPort, gotDstPort = decodeUDPPacket(t, reverseOut)
	if !bytes.Equal(gotDstMAC[:], clientMAC[:]) {
		t.Fatalf("reverse dst mac = %x, want %x", gotDstMAC, clientMAC)
	}
	if !bytes.Equal(gotSrcMAC[:], relayMAC[:]) {
		t.Fatalf("reverse src mac = %x, want %x", gotSrcMAC, relayMAC)
	}
	if gotSrcIP.String() != relayIP {
		t.Fatalf("reverse src ip = %s, want %s", gotSrcIP, relayIP)
	}
	if gotDstIP.String() != clientIP {
		t.Fatalf("reverse dst ip = %s, want %s", gotDstIP, clientIP)
	}
	if gotSrcPort != relayPort {
		t.Fatalf("reverse src port = %d, want %d", gotSrcPort, relayPort)
	}
	if gotDstPort != clientPort {
		t.Fatalf("reverse dst port = %d, want %d", gotDstPort, clientPort)
	}
}

func TestTCForwardAndReverseRewrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	if objs.TcRelayFunc == nil {
		t.Skip("tc_relay_func not available in object")
	}

	relayIP := "10.10.0.1"
	targetIP := "172.16.8.9"
	clientIP := "192.168.50.100"

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	nextHopMAC := [6]byte{0x02, 0xde, 0xad, 0xbe, 0xef, 0x10}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	targetMAC := [6]byte{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}

	const relayPort = uint16(9999)
	const targetPort = uint16(11786)
	const clientPort = uint16(54321)

	if err := writeRelayRule(objs.ConfigMap, relayPort, relayIP, targetIP, targetPort, relayMAC, nextHopMAC, 0, 0); err != nil {
		t.Fatalf("write relay rule: %v", err)
	}

	forwardIn := buildUDPPacket(
		clientMAC,
		relayMAC,
		udpTuple{
			srcIP:   clientIP,
			dstIP:   relayIP,
			srcPort: clientPort,
			dstPort: relayPort,
		},
	)

	ret, forwardOut, err := objs.TcRelayFunc.Test(forwardIn)
	if err != nil {
		t.Fatalf("tc forward test: %v", err)
	}
	if ret != tcRedirect {
		t.Fatalf("forward action = %d, want TC_ACT_REDIRECT(%d)", ret, tcRedirect)
	}

	gotDstMAC, gotSrcMAC, gotSrcIP, gotDstIP, gotSrcPort, gotDstPort := decodeUDPPacket(t, forwardOut)
	if !bytes.Equal(gotDstMAC[:], nextHopMAC[:]) {
		t.Fatalf("forward dst mac = %x, want %x", gotDstMAC, nextHopMAC)
	}
	if !bytes.Equal(gotSrcMAC[:], relayMAC[:]) {
		t.Fatalf("forward src mac = %x, want %x", gotSrcMAC, relayMAC)
	}
	if gotSrcIP.String() != relayIP {
		t.Fatalf("forward src ip = %s, want %s", gotSrcIP, relayIP)
	}
	if gotDstIP.String() != targetIP {
		t.Fatalf("forward dst ip = %s, want %s", gotDstIP, targetIP)
	}
	if gotDstPort != targetPort {
		t.Fatalf("forward dst port = %d, want %d", gotDstPort, targetPort)
	}
	if gotSrcPort < snatMinPort || gotSrcPort > snatMaxPort {
		t.Fatalf("snat port out of range: %d", gotSrcPort)
	}

	// Replay the same flow to verify reuse path remains stable.
	ret, secondForwardOut, err := objs.TcRelayFunc.Test(forwardIn)
	if err != nil {
		t.Fatalf("tc second forward test: %v", err)
	}
	if ret != tcRedirect {
		t.Fatalf("second forward action = %d, want TC_ACT_REDIRECT(%d)", ret, tcRedirect)
	}

	_, _, secondSrcIP, secondDstIP, secondSrcPort, secondDstPort := decodeUDPPacket(t, secondForwardOut)
	if secondSrcIP.String() != relayIP || secondDstIP.String() != targetIP {
		t.Fatalf("second forward tuple ip = %s -> %s, want %s -> %s", secondSrcIP, secondDstIP, relayIP, targetIP)
	}
	if secondDstPort != targetPort {
		t.Fatalf("second forward dst port = %d, want %d", secondDstPort, targetPort)
	}
	if secondSrcPort != gotSrcPort {
		t.Fatalf("second forward snat port = %d, want %d", secondSrcPort, gotSrcPort)
	}

	reverseIn := buildUDPPacket(
		targetMAC,
		relayMAC,
		udpTuple{
			srcIP:   targetIP,
			dstIP:   relayIP,
			srcPort: targetPort,
			dstPort: gotSrcPort,
		},
	)

	ret, reverseOut, err := objs.TcRelayFunc.Test(reverseIn)
	if err != nil {
		t.Fatalf("tc reverse test: %v", err)
	}
	if ret != tcRedirect {
		t.Fatalf("reverse action = %d, want TC_ACT_REDIRECT(%d)", ret, tcRedirect)
	}

	gotDstMAC, gotSrcMAC, gotSrcIP, gotDstIP, gotSrcPort, gotDstPort = decodeUDPPacket(t, reverseOut)
	if !bytes.Equal(gotDstMAC[:], clientMAC[:]) {
		t.Fatalf("reverse dst mac = %x, want %x", gotDstMAC, clientMAC)
	}
	if !bytes.Equal(gotSrcMAC[:], relayMAC[:]) {
		t.Fatalf("reverse src mac = %x, want %x", gotSrcMAC, relayMAC)
	}
	if gotSrcIP.String() != relayIP {
		t.Fatalf("reverse src ip = %s, want %s", gotSrcIP, relayIP)
	}
	if gotDstIP.String() != clientIP {
		t.Fatalf("reverse dst ip = %s, want %s", gotDstIP, clientIP)
	}
	if gotSrcPort != relayPort {
		t.Fatalf("reverse src port = %d, want %d", gotSrcPort, relayPort)
	}
	if gotDstPort != clientPort {
		t.Fatalf("reverse dst port = %d, want %d", gotDstPort, clientPort)
	}
}

func TestXDPNoRulePass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildUDPPacket(clientMAC, relayMAC, udpTuple{
		srcIP:   "192.168.1.10",
		dstIP:   "10.0.0.1",
		srcPort: 50000,
		dstPort: 9999,
	})

	ret, _, err := objs.XdpRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("xdp no-rule test: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("action = %d, want XDP_PASS(%d)", ret, xdpPass)
	}
}

func TestTCNoRulePass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	if objs.TcRelayFunc == nil {
		t.Skip("tc_relay_func not available in object")
	}

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildUDPPacket(clientMAC, relayMAC, udpTuple{
		srcIP:   "192.168.1.10",
		dstIP:   "10.0.0.1",
		srcPort: 50000,
		dstPort: 9999,
	})

	ret, _, err := objs.TcRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("tc no-rule test: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("action = %d, want TC_ACT_OK(%d)", ret, tcActOK)
	}
}

func TestXDPReverseWithoutSessionPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	targetMAC := [6]byte{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}
	p := buildUDPPacket(targetMAC, relayMAC, udpTuple{
		srcIP:   "172.16.8.9",
		dstIP:   "10.10.0.1",
		srcPort: 11786,
		dstPort: 60000,
	})

	ret, _, err := objs.XdpRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("xdp reverse-without-session test: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("action = %d, want XDP_PASS(%d)", ret, xdpPass)
	}
}

func TestTCReverseWithoutSessionPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	if objs.TcRelayFunc == nil {
		t.Skip("tc_relay_func not available in object")
	}

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	targetMAC := [6]byte{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}
	p := buildUDPPacket(targetMAC, relayMAC, udpTuple{
		srcIP:   "172.16.8.9",
		dstIP:   "10.10.0.1",
		srcPort: 11786,
		dstPort: 60000,
	})

	ret, _, err := objs.TcRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("tc reverse-without-session test: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("action = %d, want TC_ACT_OK(%d)", ret, tcActOK)
	}
}

func TestXDPFragmentPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildUDPPacket(clientMAC, relayMAC, udpTuple{
		srcIP:   "192.168.1.10",
		dstIP:   "10.0.0.1",
		srcPort: 50000,
		dstPort: 9999,
	})
	// Set MF flag to simulate fragmented IPv4 packet.
	binary.BigEndian.PutUint16(p[ethHdrLen+6:ethHdrLen+8], 0x2000)

	ret, _, err := objs.XdpRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("xdp fragment test: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("action = %d, want XDP_PASS(%d)", ret, xdpPass)
	}
}

func TestTCFragmentPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	if objs.TcRelayFunc == nil {
		t.Skip("tc_relay_func not available in object")
	}

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildUDPPacket(clientMAC, relayMAC, udpTuple{
		srcIP:   "192.168.1.10",
		dstIP:   "10.0.0.1",
		srcPort: 50000,
		dstPort: 9999,
	})
	binary.BigEndian.PutUint16(p[ethHdrLen+6:ethHdrLen+8], 0x2000)

	ret, _, err := objs.TcRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("tc fragment test: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("action = %d, want TC_ACT_OK(%d)", ret, tcActOK)
	}
}

func TestXDPUnsupportedProtocolPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildIPv4Packet(clientMAC, relayMAC, ipProtoICMP, "192.168.1.10", "10.0.0.1")

	ret, _, err := objs.XdpRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("xdp unsupported-protocol test: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("action = %d, want XDP_PASS(%d)", ret, xdpPass)
	}
}

func TestTCUnsupportedProtocolPass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}

	objs := mustLoadRelayObjectsForTest(t)
	defer objs.Close()

	if objs.TcRelayFunc == nil {
		t.Skip("tc_relay_func not available in object")
	}

	relayMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	clientMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := buildIPv4Packet(clientMAC, relayMAC, ipProtoICMP, "192.168.1.10", "10.0.0.1")

	ret, _, err := objs.TcRelayFunc.Test(p)
	if err != nil {
		t.Fatalf("tc unsupported-protocol test: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("action = %d, want TC_ACT_OK(%d)", ret, tcActOK)
	}
}

func mustLoadRelayObjectsForTest(t *testing.T) *relayObjects {
	t.Helper()

	spec, err := ebpf.LoadCollectionSpec("../relay_bpfel.o")
	if err != nil {
		t.Fatalf("load relay_bpfel.o: %v", err)
	}

	objs := &relayObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("load and assign bpf objects: %v", err)
	}
	return objs
}

func writeRelayRule(m *ebpf.Map, relayPort uint16, relayIP, targetIP string, targetPort uint16, relayMAC, nextHopMAC [6]byte, relayIfindex, txIfindex uint32) error {
	key := make([]byte, 2)
	binary.LittleEndian.PutUint16(key, htons(relayPort))

	// struct relay_rule size is 32 bytes after adding padding for alignment
	val := make([]byte, 32)
	binary.LittleEndian.PutUint32(val[0:4], ip4ToU32LE(relayIP))
	binary.LittleEndian.PutUint32(val[4:8], ip4ToU32LE(targetIP))
	binary.LittleEndian.PutUint16(val[8:10], htons(targetPort))
	copy(val[10:16], relayMAC[:])
	copy(val[16:22], nextHopMAC[:])
	// val[22:24] is padding (pad in C struct)
	binary.LittleEndian.PutUint32(val[24:28], relayIfindex)
	binary.LittleEndian.PutUint32(val[28:32], txIfindex)

	return m.Update(key, val, ebpf.UpdateAny)
}

func ip4ToU32LE(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

func buildUDPPacket(srcMAC, dstMAC [6]byte, tuple udpTuple) []byte {
	b := make([]byte, ethHdrLen+ipv4HdrLen+udpHdrLen)

	copy(b[0:6], dstMAC[:])
	copy(b[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(b[12:14], ipv4EthType)

	ipStart := ethHdrLen
	b[ipStart+0] = 0x45
	b[ipStart+1] = 0
	binary.BigEndian.PutUint16(b[ipStart+2:ipStart+4], uint16(ipv4HdrLen+udpHdrLen))
	binary.BigEndian.PutUint16(b[ipStart+4:ipStart+6], 0)
	binary.BigEndian.PutUint16(b[ipStart+6:ipStart+8], 0)
	b[ipStart+8] = 64
	b[ipStart+9] = ipProtoUDP

	srcIP := net.ParseIP(tuple.srcIP).To4()
	dstIP := net.ParseIP(tuple.dstIP).To4()
	copy(b[ipStart+12:ipStart+16], srcIP)
	copy(b[ipStart+16:ipStart+20], dstIP)
	binary.BigEndian.PutUint16(b[ipStart+10:ipStart+12], ipv4Checksum(b[ipStart:ipStart+ipv4HdrLen]))

	udpStart := ethHdrLen + ipv4HdrLen
	binary.BigEndian.PutUint16(b[udpStart+0:udpStart+2], tuple.srcPort)
	binary.BigEndian.PutUint16(b[udpStart+2:udpStart+4], tuple.dstPort)
	binary.BigEndian.PutUint16(b[udpStart+4:udpStart+6], udpHdrLen)
	binary.BigEndian.PutUint16(b[udpStart+6:udpStart+8], 0)

	return b
}

func buildIPv4Packet(srcMAC, dstMAC [6]byte, proto uint8, srcIP, dstIP string) []byte {
	b := make([]byte, ethHdrLen+ipv4HdrLen)
	copy(b[0:6], dstMAC[:])
	copy(b[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(b[12:14], ipv4EthType)

	ipStart := ethHdrLen
	b[ipStart+0] = 0x45
	b[ipStart+1] = 0
	binary.BigEndian.PutUint16(b[ipStart+2:ipStart+4], uint16(ipv4HdrLen))
	binary.BigEndian.PutUint16(b[ipStart+4:ipStart+6], 0)
	binary.BigEndian.PutUint16(b[ipStart+6:ipStart+8], 0)
	b[ipStart+8] = 64
	b[ipStart+9] = proto

	copy(b[ipStart+12:ipStart+16], net.ParseIP(srcIP).To4())
	copy(b[ipStart+16:ipStart+20], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(b[ipStart+10:ipStart+12], ipv4Checksum(b[ipStart:ipStart+ipv4HdrLen]))
	return b
}

func decodeUDPPacket(t *testing.T, p []byte) (dstMAC, srcMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16) {
	t.Helper()
	minLen := ethHdrLen + ipv4HdrLen + udpHdrLen
	if len(p) < minLen {
		t.Fatalf("packet too short: %d", len(p))
	}
	copy(dstMAC[:], p[0:6])
	copy(srcMAC[:], p[6:12])

	srcIP = net.IPv4(p[26], p[27], p[28], p[29]).To4()
	dstIP = net.IPv4(p[30], p[31], p[32], p[33]).To4()
	srcPort = binary.BigEndian.Uint16(p[34:36])
	dstPort = binary.BigEndian.Uint16(p[36:38])
	return
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
