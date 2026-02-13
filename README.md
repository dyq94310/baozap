go get -tool github.com/cilium/ebpf/cmd/bpf2go

go generate
go build 

cat /sys/kernel/debug/tracing/trace_pipe

函数,全称,用途
bpf_ntohs,Network to Host Short,解析数据包时，将 16 位端口转为本地数字。
bpf_htons,Host to Network Short,构造/修改数据包时，将本地数字转为网络格式。
bpf_ntohl,Network to Host Long,解析 IP 地址 (32位) 时使用。
bpf_htonl,Host to Network Long,IP 地址 (32位) 转网络格式。

// clang-format off
//go:build ignore
// clang-format on


本仓库已包含预编译的 eBPF 字节码（Go 文件）。若需修改内核态代码 relay.c，请确保本地已安装 clang 和 llvm，并运行 go generate 重新生成代码。

## todo list

- 实现UDP转发
- 优化主机序和网络序的分层逻辑
- 完善文档
- 引入Cobra实现cmd cli
- 进行benchmark对比
- 多平台支持
- 进行必要的推广