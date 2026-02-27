package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type Config struct {
	Interface string `json:"interface"`
	Debug     bool   `json:"debug"` // JSON 中不写则默认为 false
	Rules     []struct {
		RelayPort  uint16 `json:"relay_port"`
		TargetIP   string `json:"target_ip"`
		TargetPort uint16 `json:"target_port"`
	} `json:"rules"`
}

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

	if conf.Debug {
		// 直接在 Spec 加载前设置初始值
		// Set 会根据变量类型自动进行类型转换检查
		if err := spec.Variables["debug_enabled"].Set(uint32(1)); err != nil {
			log.Fatalf("failed to set debug_enabled: %v", err)
		}
	}

	// 3. 将修改后的 Spec 加载到内核对象中
	objs := relayObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}

	fmt.Printf("🛠  Debug Logging Enabled: %v\n", conf.Debug)

	defer objs.Close()

	for _, rule := range conf.Rules {
		lIP, lMAC, nMAC, err := probeNetwork(conf.Interface, rule.TargetIP)
		if err != nil {
			fmt.Printf("⚠️ Skip rule %d: %v\n", rule.RelayPort, err)
			continue
		}

		tip, err := ip4ToU32LE(net.ParseIP(rule.TargetIP))
		if err != nil {
			fmt.Printf("⚠️ Skip rule %d: invalid target ip: %v\n", rule.RelayPort, err)
			continue
		}

		cfg := relayRelayRule{
			RelayIp:    lIP,                    // raw little-endian uint32
			TargetIp:   tip,                    // raw little-endian uint32
			TargetPort: htons(rule.TargetPort), // raw network-order uint16
			RelayMac:   lMAC,
			NextHopMac: nMAC,
		}

		portKey := htons(rule.RelayPort)
		if err := objs.ConfigMap.Update(portKey, &cfg, ebpf.UpdateAny); err != nil {
			log.Fatalf("Update map failed: %v", err)
		}
		fmt.Printf("✅ Added: :%d -> %s:%d\n", rule.RelayPort, rule.TargetIP, rule.TargetPort)
	}

	iface, err := net.InterfaceByName(conf.Interface)
	if err != nil {
		log.Fatalf("InterfaceByName: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRelayFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("🚀 XDP program attached to interface %s\n", conf.Interface)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func probeNetwork(ifaceName, targetIPStr string) (uint32, [6]byte, [6]byte, error) {
	nl, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return 0, [6]byte{}, [6]byte{}, err
	}

	addrs, err := netlink.AddrList(nl, netlink.FAMILY_V4)
	if err != nil || len(addrs) == 0 {
		return 0, [6]byte{}, [6]byte{}, fmt.Errorf("no ipv4 addr on %s", ifaceName)
	}

	var lMAC, nMAC [6]byte
	copy(lMAC[:], nl.Attrs().HardwareAddr)

	localIPv4 := addrs[0].IP.To4()
	if localIPv4 == nil {
		return 0, [6]byte{}, [6]byte{}, fmt.Errorf("invalid local ipv4 on %s", ifaceName)
	}
	localIP := binary.LittleEndian.Uint32(localIPv4)

	routes, err := netlink.RouteGet(net.ParseIP(targetIPStr))
	if err != nil || len(routes) == 0 {
		return 0, lMAC, nMAC, fmt.Errorf("no route to %s", targetIPStr)
	}

	gw := routes[0].Gw
	if gw == nil {
		gw = net.ParseIP(targetIPStr)
	}
	gw = gw.To4()
	if gw == nil {
		return 0, lMAC, nMAC, fmt.Errorf("invalid gateway ip for %s", targetIPStr)
	}

	for i := 0; i < 3; i++ {
		neighs, _ := netlink.NeighList(nl.Attrs().Index, netlink.FAMILY_V4)
		for _, n := range neighs {
			if n.IP != nil && n.IP.Equal(gw) && n.HardwareAddr != nil {
				copy(nMAC[:], n.HardwareAddr)
				return localIP, lMAC, nMAC, nil
			}
		}

		// 使用 UDP 报文触发内核邻居解析，避免依赖外部 ping 命令。
		if conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: localIPv4}, &net.UDPAddr{IP: gw, Port: 9}); err == nil {
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}

	return localIP, lMAC, lMAC, fmt.Errorf("ARP not found for gateway %s", gw)
}
