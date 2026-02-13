package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type Config struct {
	Interface string `json:"interface"`
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

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {

	// 1. 读取配置文件
	confFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer confFile.Close()

	var conf Config
	if err := json.NewDecoder(confFile).Decode(&conf); err != nil {
		log.Fatalf("Failed to decode config: %v", err)
	}

	// 1. 加载生成的 BPF 对象
	objs := relayObjects{}
	if err := loadRelayObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	for _, rule := range conf.Rules {
		// 2. 探测网络信息 (MAC/IP/网关)
		lIP, lMAC, nMAC, err := probeNetwork(conf.Interface, rule.TargetIP)
		if err != nil {
			fmt.Printf("⚠️ Skip rule %d: %v\n", rule.RelayPort, err)
			continue
		}

		// 3. 使用生成的结构体填充 Map (注意：全部使用主机序存储)
		cfg := relayRelayRule{
			RelayIp:    lIP,
			TargetIp:   binary.LittleEndian.Uint32(net.ParseIP(rule.TargetIP).To4()),
			TargetPort: htons(rule.TargetPort),
			RelayMac:   lMAC,
			NextHopMac: nMAC,
		}
		portKey := htons(rule.RelayPort)
		if err := objs.ConfigMap.Update(portKey, &cfg, ebpf.UpdateAny); err != nil {
			log.Fatalf("Update map failed: %v", err)
		}
		fmt.Printf("✅ Added: :%d -> %s:%d\n", rule.RelayPort, rule.TargetIP, rule.TargetPort)
	}

	// 4. 挂载 XDP 程序
	iface, err := net.InterfaceByName(conf.Interface)
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
	link, _ := netlink.LinkByName(ifaceName)
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	var lMAC, nMAC [6]byte
	copy(lMAC[:], link.Attrs().HardwareAddr)
	localIP := binary.LittleEndian.Uint32(addrs[0].IP.To4())

	routes, _ := netlink.RouteGet(net.ParseIP(targetIPStr))
	if len(routes) == 0 {
		return 0, lMAC, nMAC, fmt.Errorf("no route")
	}
	gw := routes[0].Gw
	if gw == nil {
		gw = net.ParseIP(targetIPStr)
	}

	// 强制触发一次 ARP 学习，防止邻居表为空
	exec.Command("ping", "-c", "1", "-W", "1", gw.String()).Run()

	neighs, _ := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	for _, n := range neighs {
		if n.IP.Equal(gw) {
			copy(nMAC[:], n.HardwareAddr)
			return localIP, lMAC, nMAC, nil
		}
	}
	return localIP, lMAC, lMAC, fmt.Errorf("ARP not found for gateway %s", gw)
}
