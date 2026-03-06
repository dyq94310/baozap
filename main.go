package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Config struct {
	Mode  string `json:"mode"`  // "xdp" or "tc"
	Debug bool   `json:"debug"` // JSON 中不写则默认为 false
	Rules []struct {
		RelayInterface  string `json:"relay_interface"`
		TargetInterface string `json:"target_interface"`
		RelayPort       uint16 `json:"relay_port"`
		TargetIP        string `json:"target_ip"`
		TargetPort      uint16 `json:"target_port"`
	} `json:"rules"`
}

var version = "dev"

/*
* 约定
* go：负责主机序到BPF网络序的转换，负责繁琐工作
* c：BPF：直接接收网络序,专注处理中继逻辑
 */

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

func ip4ToU32LE(ip net.IP) (uint32, error) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not ipv4: %v", ip)
	}
	return binary.LittleEndian.Uint32(v4), nil
}

func main() {
	if isVersionFlagRequested() {
		fmt.Println(version)
		return
	}

	confFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer confFile.Close()

	var conf Config
	if err := json.NewDecoder(confFile).Decode(&conf); err != nil {
		log.Fatalf("Failed to decode config: %v", err)
	}

	spec, err := loadRelay() // 函数名来自于你生成的源码
	if err != nil {
		log.Fatalf("failed to load bpf spec: %v", err)
	}

	// 3. 将修改后的 Spec 加载到内核对象中
	objs := relayObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}

	defer objs.Close()

	attachIfs := map[int]string{}
	for _, rule := range conf.Rules {
		relayIf := rule.RelayInterface
		targetIf := rule.TargetInterface
		if targetIf == "" {
			targetIf = relayIf
		}
		if relayIf == "" || targetIf == "" {
			fmt.Printf("⚠️ Skip rule %d: relay_interface/target_interface is required\n", rule.RelayPort)
			continue
		}

		snatIP, relayIfindex, err := probeNetwork(relayIf, targetIf)
		if err != nil {
			fmt.Printf("⚠️ Skip rule %d: %v\n", rule.RelayPort, err)
			continue
		}

		tip, err := ip4ToU32LE(net.ParseIP(rule.TargetIP))
		if err != nil {
			fmt.Printf("⚠️ Skip rule %d: invalid target ip: %v\n", rule.RelayPort, err)
			continue
		}

		val := buildRelayRuleValue(
			snatIP,
			tip,
			htons(rule.TargetPort), // raw network-order uint16
			[6]byte{},
			[6]byte{},
			relayIfindex,
			0,
		)

		portKey := htons(rule.RelayPort)
		if err := objs.ConfigMap.Update(portKey, val, ebpf.UpdateAny); err != nil {
			log.Fatalf("Update map failed: %v", err)
		}
		fmt.Printf(
			"✅ Added: %s/%s :%d -> %s:%d (relay_ifindex=%d)\n",
			relayIf, targetIf, rule.RelayPort, rule.TargetIP, rule.TargetPort,
			relayIfindex,
		)

		if lnk, err := netlink.LinkByName(relayIf); err == nil && lnk.Attrs() != nil {
			attachIfs[lnk.Attrs().Index] = relayIf
		}
		if lnk, err := netlink.LinkByName(targetIf); err == nil && lnk.Attrs() != nil {
			attachIfs[lnk.Attrs().Index] = targetIf
		}
	}

	if len(attachIfs) == 0 {
		log.Fatalf("no valid rules loaded; nothing to attach")
	}

	mode := strings.ToLower(conf.Mode)
	if mode == "" {
		mode = "tc"
	}

	var links []io.Closer
	for ifidx, ifname := range attachIfs {
		if mode == "tc" {
			l, err := attachTCIngress(objs.TcRelayFunc, ifidx, ifname)
			if err != nil {
				log.Fatalf("Attach TC on %s(%d): %v", ifname, ifidx, err)
			}
			links = append(links, l)
			fmt.Printf("🚀 TC program attached to interface %s (hook=clsact/ingress)\n", ifname)
		} else {
			l, xdpMode, err := attachXDPWithFallback(objs.XdpRelayFunc, ifidx, ifname)
			if err != nil {
				log.Fatalf("Attach XDP on %s(%d): %v", ifname, ifidx, err)
			}
			links = append(links, l)
			fmt.Printf("🚀 XDP program attached to interface %s (mode=%s)\n", ifname, xdpMode)
		}
	}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func isVersionFlagRequested() bool {
	for _, arg := range os.Args[1:] {
		if arg == "-v" || arg == "--version" {
			return true
		}
	}
	return false
}

func probeNetwork(relayIfaceName, targetIfaceName string) (uint32, int, error) {
	relayLink, err := netlink.LinkByName(relayIfaceName)
	if err != nil {
		return 0, 0, err
	}
	targetLink, err := netlink.LinkByName(targetIfaceName)
	if err != nil {
		return 0, 0, err
	}
	if relayLink.Attrs() == nil || targetLink.Attrs() == nil {
		return 0, 0, fmt.Errorf("invalid interface attrs for %s/%s", relayIfaceName, targetIfaceName)
	}

	targetAddrs, err := netlink.AddrList(targetLink, netlink.FAMILY_V4)
	if err != nil || len(targetAddrs) == 0 {
		return 0, 0, fmt.Errorf("no ipv4 addr on target interface %s", targetIfaceName)
	}

	snatIPv4 := targetAddrs[0].IP.To4()
	if snatIPv4 == nil {
		return 0, 0, fmt.Errorf("invalid local ipv4 on target interface %s", targetIfaceName)
	}
	snatIP := binary.LittleEndian.Uint32(snatIPv4)
	relayIfindex := relayLink.Attrs().Index

	return snatIP, relayIfindex, nil
}

func buildRelayRuleValue(relayIP, targetIP uint32, targetPort uint16, relayMAC, nextHopMAC [6]byte, relayIfindex, txIfindex int) []byte {
	val := make([]byte, 30)
	binary.LittleEndian.PutUint32(val[0:4], relayIP)
	binary.LittleEndian.PutUint32(val[4:8], targetIP)
	binary.LittleEndian.PutUint16(val[8:10], targetPort)
	copy(val[10:16], relayMAC[:])
	copy(val[16:22], nextHopMAC[:])
	binary.LittleEndian.PutUint32(val[22:26], uint32(relayIfindex))
	binary.LittleEndian.PutUint32(val[26:30], uint32(txIfindex))
	return val
}

func attachXDPWithFallback(prog *ebpf.Program, ifIndex int, ifName string) (io.Closer, string, error) {
	var tryModes []struct {
		name  string
		flags link.XDPAttachFlags
	}
	// veth + redirect 场景优先 generic，兼容性更稳定。
	if strings.HasPrefix(ifName, "veth") {
		tryModes = []struct {
			name  string
			flags link.XDPAttachFlags
		}{
			{name: "generic", flags: link.XDPGenericMode},
			{name: "driver", flags: link.XDPDriverMode},
		}
	} else {
		tryModes = []struct {
			name  string
			flags link.XDPAttachFlags
		}{
			{name: "driver", flags: link.XDPDriverMode},
			{name: "generic", flags: link.XDPGenericMode},
		}
	}

	var errs []string
	for i, m := range tryModes {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     m.flags,
		})
		if err == nil {
			return l, m.name, nil
		}

		errs = append(errs, fmt.Sprintf("%s: %v", m.name, err))
		if i == 0 && !isXDPModeUnsupported(err) {
			return nil, "", err
		}
	}

	return nil, "", fmt.Errorf("failed to attach xdp in all modes (%s)", strings.Join(errs, "; "))
}

func attachTCIngress(prog *ebpf.Program, ifIndex int, ifName string) (io.Closer, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIndex,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		return l, nil
	}

	// 内核 < 6.6 不支持 TCX，退回传统 tc-bpf 注入。
	if strings.Contains(strings.ToLower(err.Error()), "tcx not supported") {
		fmt.Printf("⚠️  TCX not supported on %s(%d), falling back to classic tc-bpf\n", ifName, ifIndex)
		return attachTCClassic(prog, ifIndex, ifName)
	}

	return nil, fmt.Errorf("attach tcx ingress on %s(%d): %w", ifName, ifIndex, err)
}

type classicTCLink struct {
	filter *netlink.BpfFilter
}

func (c *classicTCLink) Close() error {
	if c == nil || c.filter == nil {
		return nil
	}
	return netlink.FilterDel(c.filter)
}

func attachTCClassic(prog *ebpf.Program, ifIndex int, ifName string) (io.Closer, error) {
	// 确保 clsact qdisc 存在
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return nil, fmt.Errorf("qdisc add clsact on %s(%d): %w", ifName, ifIndex, err)
		}
	}

	// 在 ingress 上挂 bpf filter，direct-action 模式
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "tc_relay",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(f); err != nil {
		return nil, fmt.Errorf("attach classic tc-bpf on %s(%d): %w", ifName, ifIndex, err)
	}

	return &classicTCLink{filter: f}, nil
}

func isXDPModeUnsupported(err error) bool {
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "operation not supported")
}
