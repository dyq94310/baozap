# Testing Guide

本目录用于存放项目测试代码与测试说明。

## 目录

- `xdp_relay_test.go`: eBPF/XDP 集成测试，重点验证 `bpf/relay.c` 的转发与回包改写行为

## 覆盖内容

`TestXDPForwardAndReverseRewrite` 主要覆盖：

1. 正向转发路径：`Client -> Relay -> Target`
2. 反向回包路径：`Target -> Relay -> Client`
3. 关键字段改写正确性：
   - 二层：源/目的 MAC
   - 三层：源/目的 IPv4
   - 四层：源/目的 UDP 端口
4. SNAT 端口分配范围（`49152..65535`）

## 运行方式

在仓库根目录执行：

```bash
# Makefile 方式（推荐）
make test
make test-xdp

# 运行全部测试包
go test ./...

# 只运行 test 目录中的用例
go test ./test -v

# 指定运行 eBPF/XDP 测试（需要 root 或等效能力）
sudo -E go test ./test -run TestXDPForwardAndReverseRewrite -v
```

## 注意事项

- eBPF/XDP 测试依赖内核能力与权限，非 root 环境会自动跳过。
- 测试会加载仓库根目录下的 `relay_bpfel.o`，若修改了 `bpf/relay.c`，请先重新生成：

```bash
go generate ./...
```
