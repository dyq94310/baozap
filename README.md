# baozap

`baozap` 是一个基于 `Go + eBPF(XDP)` 的 L4 中继程序。
它在网卡入口直接处理 IPv4 TCP/UDP 数据包，将访问本机中继端口的流量转发到目标服务，并对返回流量做反向改写后回给客户端。

## 说明

本人不熟悉go和c在开发过程中大量使用了 AI vibe coding

## 特性

- 基于 XDP，包处理路径短，适合高性能转发场景
- 支持 TCP 和 UDP
- 支持多条端口转发规则
- 基于 `LRU_HASH` 维护会话映射，适配 UDP 无连接特性
- 支持内核态 debug 日志开关（`bpf_printk`）

## 工作原理

1. 用户态读取 `config.json`，把端口规则写入 `config_map`。
2. 用户态探测本机 IP/MAC 与下一跳 MAC，填入规则。
3. XDP 程序挂载到指定网卡后：
   - 正向：`Client -> Relay(relay_port) -> Target(target_ip:target_port)`
   - 反向：`Target -> Relay(snat_port) -> Client`
4. 内核态使用 `fwd_map` / `rev_map` 建立会话，并做 IP/L4 校验和增量更新。

## XDP、TC、Netfilter 的流程关系

在 Linux 收包路径里，三者大致位置如下（简化）：

```text
NIC RX
  -> XDP (driver early hook)
    -> skb 分配与协议栈
      -> TC ingress (clsact)
        -> Netfilter PREROUTING
          -> 路由 / FORWARD / INPUT / OUTPUT / POSTROUTING
            -> TC egress
              -> NIC TX
```

可以理解为：

- `XDP`：最靠前，包刚进网卡驱动就处理，很多情况下还没创建 `skb`
- `TC`：在 `skb` 阶段做分类/动作，能力强，但处理成本高于 XDP
- `Netfilter`：在完整协议栈路径上做连接跟踪/NAT/防火墙，功能最丰富，开销也通常更高

### 为什么本项目选择 XDP 转发

`baozap` 的目标是高性能 L4 中继，核心是“尽早改包并直接回发（`XDP_TX`）”：

1. 处理更早
   - 在驱动层处理包，绕过大段通用协议栈路径。
2. 内存与元数据成本更低
   - 避免（或减少）`skb` 分配、拷贝和后续栈处理。
3. 指令路径更短
   - 命中会话后直接做地址/端口/MAC 改写并发包，减少层层钩子遍历。
4. 更稳定的高包率表现
   - 在小包、高 PPS 场景下，XDP 通常比 TC / Netfilter 更容易维持低延迟和高吞吐。

### 与 TC / Netfilter 的取舍

- 选 XDP：追求极致转发性能，逻辑相对聚焦（如本项目的 L4 relay/NAT）。
- 选 TC：需要更复杂的队列、整形、分类联动，且可接受更高开销。
- 选 Netfilter：需要成熟的 conntrack、iptables/nftables 生态与通用防火墙能力。

本项目当前定位是“性能优先的端口转发中继”，因此优先采用 XDP 路径。

## 目录结构

- `main.go`: 用户态入口，加载配置、写 map、挂载 XDP
- `bpf/relay.c`: eBPF 内核态转发逻辑
- `gen.go`: `bpf2go` 代码生成入口
- `relay_bpf*.go`, `relay_bpf*.o`: 生成产物（按架构/端序）
- `config.json`: 运行配置
- `Makefile`: 构建和远程部署脚本

## 环境要求

- Linux（需支持 XDP/eBPF）
- Go `1.25+`（`go.mod` 当前为 `1.25.0`）
- 如需重新生成 eBPF 代码：`clang`、`llvm`、`libbpf` 相关头文件
- 运行时通常需要 root（或等效 `CAP_BPF`/`CAP_NET_ADMIN` 权限）

## 快速开始

### 1. 安装 bpf2go 工具

```bash
go get -tool github.com/cilium/ebpf/cmd/bpf2go
```

### 2. 生成并编译

```bash
go generate ./...
go build -o baozap .
```

### 3. 配置转发规则

编辑 `config.json`：

```json
{
  "interface": "wlp2s0",
  "debug": false,
  "rules": [
    {
      "relay_port": 9999,
      "target_ip": "161.248.136.126",
      "target_port": 11786
    },
    {
      "relay_port": 9998,
      "target_ip": "161.248.136.126",
      "target_port": 11782
    }
  ]
}
```

字段说明：

- `interface`: 要挂载 XDP 的网卡名
- `debug`: 是否开启内核 debug 日志（可选，默认 `false`）
- `rules[].relay_port`: 本机对外提供的中继端口
- `rules[].target_ip`: 目标服务 IPv4 地址
- `rules[].target_port`: 目标服务端口

### 4. 运行

```bash
sudo ./baozap
```

程序会在启动时打印规则加载与 XDP 挂载信息。

## 调试

启用 `debug: true` 后，可查看内核态日志：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Docker

仓库提供两种镜像构建方式：

- `Dockerfile`: 在镜像内完整构建（包含 `go generate`）
- `Dockerfile.binary`: 仅打包外部已构建好的二进制（多架构发布流程使用）

GitHub Actions 工作流位于 `.github/workflows/docker.yml`，会构建 `amd64/arm64` 并发布到 GHCR。

## 常见问题

1. `Attach XDP` 失败
   - 检查是否 root 权限
   - 检查网卡是否支持 XDP 驱动模式（必要时考虑 generic 模式扩展）

2. 规则添加成功但不转发
   - 确认 `interface` 是实际收包网卡
   - 确认目标 IP 路由可达
   - 确认网关 ARP 可解析（程序启动时会尝试探测）

3. 修改了 `bpf/relay.c` 但行为未变化
   - 需要重新执行 `go generate ./...` 再重新构建运行

## 开发说明

- 本仓库已包含预编译 eBPF 生成文件，可直接 `go build`
- 若修改 `bpf/relay.c`，请重新生成：

```bash
go generate ./...
```
