package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func main() {
	ifaceName := "ens5" // 你的网卡名
	// targetIPStr := "126.136.248.161"
	targetIPStr := "161.248.136.126"

	// 1. 加载生成的 BPF 对象
	objs := relayObjects{}
	if err := loadRelayObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// 2. 探测网络信息 (MAC/IP/网关)
	lIP, lMAC, nMAC, err := probeNetwork(ifaceName, targetIPStr)
	if err != nil {
		log.Fatalf("Network probe: %v", err)
	}

	// 3. 使用生成的结构体填充 Map (注意：全部使用主机序存储)
	cfg := relayRelayConfig{
		RelayIp:    binary.BigEndian.Uint32(net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", byte(lIP), byte(lIP>>8), byte(lIP>>16), byte(lIP>>24))).To4()),
		TargetIp:   binary.BigEndian.Uint32(net.ParseIP(targetIPStr).To4()),
		RelayPort:  9999,
		TargetPort: 11786,
		RelayMac:   lMAC,
		NextHopMac: nMAC,
	}

	if err := objs.ConfigMap.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
		log.Fatalf("Update map failed: %v", err)
	}

	// 4. 挂载 XDP 程序
	iface, _ := net.InterfaceByName(ifaceName)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRelayFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("🚀 Relay Running: :9999 -> %s:11786\n", targetIPStr)
	fmt.Printf("Local IP: %s, NextHop MAC: %x\n", net.IPv4(byte(lIP), byte(lIP>>8), byte(lIP>>16), byte(lIP>>24)), nMAC)

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
