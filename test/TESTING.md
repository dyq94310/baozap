# Testing Guide

本目录用于存放项目测试代码与测试说明。

## 目录

- `xdp_relay_test.go`: eBPF/XDP 集成测试（build tag: `xdp_integration`）
- `../main_test.go`: Go 单元测试（不依赖 root）

## 覆盖内容

### Go 单元测试

覆盖：

1. `ip4ToU32LE` 正常/异常输入
2. `-v/--version` 参数识别
3. XDP 挂载模式错误判定（`isXDPModeUnsupported`）

### eBPF 集成测试

正向与反向主链路：

1. `TestXDPForwardAndReverseRewrite`
2. `TestTCForwardAndReverseRewrite`
3. `TestTCForwardAndReverseRewriteTCPPreservesPayload`
2. 关键字段改写正确性：
   - 二层：源/目的 MAC
   - 三层：源/目的 IPv4
   - 四层：TCP/UDP 源/目的端口
   - 校验和：IPv4 / TCP 改写后保持正确
   - 负载：TC TCP 改写后 payload 不变
3. SNAT 端口分配范围（`49152..65535`）

反例与异常场景：

1. `TestXDPNoRulePass`：无规则命中时 `XDP_PASS`
2. `TestXDPReverseWithoutSessionPass`：无会话反向包时 `XDP_PASS`
3. `TestXDPFragmentPass`：分片包时 `XDP_PASS`
4. `TestXDPUnsupportedProtocolPass`：非 TCP/UDP（如 ICMP）时 `XDP_PASS`
5. `TestTCNoRulePass` / `TestTCReverseWithoutSessionPass` / `TestTCFragmentPass` / `TestTCUnsupportedProtocolPass`

## 运行方式

在仓库根目录执行：

```bash
# Go 单元测试（不依赖 root）
make test-go

# XDP 集成测试（依赖 root）
make test-xdp

# 一键完整测试（Go 单测 + XDP 集成）
make test

# 直接运行 XDP 测试集（需要 root 或等效能力）
sudo -E go test ./test -tags xdp_integration -run TestXDP -v
```

## 注意事项

- eBPF/XDP 测试依赖内核能力与权限，非 root 环境会自动跳过。
- `xdp_relay_test.go` 使用 `xdp_integration` build tag，默认 `go test ./...` 不会执行。
- 测试会加载仓库根目录下的 `relay_bpfel.o`，若修改了 `bpf/relay.c`，请先重新生成：

```bash
go generate ./...
```
