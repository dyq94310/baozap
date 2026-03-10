# baozap

`baozap` 是一个基于 `Go + eBPF(XDP)` 的 L4 中继程序，用于将访问本机中继端口的 TCP/UDP 流量转发到目标服务，并对回包做反向改写。

## 特性

- XDP 快速转发路径（性能优先）
- 支持 TCP / UDP
- 多端口规则转发
- 基于 `LRU_HASH` 的会话映射
- 支持 `driver -> generic` 的 XDP 挂载回退

## 工作原理（简版）

1. 用户态读取 `config.json`，写入 `config_map`
2. 启动时探测本机 IP/MAC 与下一跳 MAC
3. XDP 处理转发与回包改写：
   - 正向：`Client -> Relay -> Target`
   - 反向：`Target -> Relay -> Client`

## 环境要求

- Linux（支持 eBPF/XDP）
- root 权限（或等效能力）

使用已发布二进制包时，不需要本地 Go 环境。

## 配置示例

`config.json`（默认使用 TC eBPF，在不升级内核的前提下对 GRO/TSO 更友好；也支持按端口覆盖 mode）：

```json
{
  "mode": "tc",
  "debug": false,
  "rules": [
    {
      "mode": "xdp",
      "relay_interface": "eth0",
      "target_interface": "eth0",
      "relay_port": 9999,
      "target_ip": "161.248.136.126",
      "target_port": 11786
    }
  ]
}
```

字段说明：

- `mode`: 顶层默认挂载模式，可选，`"tc"`（默认，使用 TC eBPF，GRO/TSO 兼容性更好，内核 < 6.6 时自动使用传统 tc-bpf 注入）或 `"xdp"`（纯 XDP，性能更高但对 offload 更敏感）
- `debug`: 是否开启内核日志
- `rules[].mode`: 可选，单端口覆盖顶层 `mode`
- `rules[].relay_interface`: 收入流量（Client -> Relay）的接口
- `rules[].target_interface`: 发往目标与接收回包（Relay <-> Target）的接口
- `rules[].relay_port`: 中继端口
- `rules[].target_ip`: 目标 IPv4
- `rules[].target_port`: 目标端口

## 二进制部署（推荐）

每个版本会在 GitHub Release 提供二进制包（Assets）：

- `baozap-<tag>-amd64.tar.gz`
- `baozap-<tag>-arm64.tar.gz`
- `sha256sums.txt`

示例（以 `v0.3.3` 和 `amd64` 为例）：

```bash
curl -LO https://github.com/dyq94310/baozap/releases/download/v0.3.3/baozap-v0.3.3-amd64.tar.gz
tar -xzf baozap-v0.3.3-amd64.tar.gz
sudo ./baozap
```

查看版本：

```bash
./baozap -v
```

## 源码运行

```bash
make build
sudo ./baozap
```

低延迟路径（默认已启用）：

- TC 路径不在热路径上做统计计数。
- 并发建连 race 的 miss 分支采用更快的直接返回策略（减少一次 map lookup）。

## Docker Compose 部署

`docker-compose.yaml`：

```yaml
services:
  baozap:
    image: ghcr.io/dyq94310/baozap:latest
    container_name: baozap
    network_mode: host
    privileged: true
    restart: always
    volumes:
      - ./config.json:/app/config.json
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

启动：

```bash
docker compose up -d
```

说明：

- `network_mode: host`：需要直接操作宿主机网卡
- `privileged: true`：需要加载 eBPF 程序与创建 map
- `config.json` 挂载到容器内 `/app/config.json`

## 排障

1. `Attach XDP` 失败：
   - 确认 root 权限
   - 确认网卡支持 XDP（程序会尝试 `driver`，失败回退 `generic`）
2. 规则生效但不转发：
   - 检查 `rules[].relay_interface` 是否为实际收包网卡
   - 检查 `rules[].target_interface` 是否为目标可达网卡
   - 检查目标路由与邻居可达性

## License

BSD 3-Clause，见 [LICENSE](./LICENSE)。
