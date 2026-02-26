# --- 第一阶段：构建环境 ---
FROM golang:1.26-bookworm AS builder

# 安装 eBPF 编译依赖
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    make \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. 设置国内代理镜像
ENV GOPROXY=https://goproxy.cn,direct

# 先拷贝依赖文件实现缓存优化
COPY go.mod go.sum ./
RUN go mod download

# 拷贝源代码
COPY . .

# 执行 go generate 编译 BPF C 代码，并构建 Go 二进制
RUN go generate -v ./... && \
    go build -v -o baozap .

# --- 第二阶段：运行环境 ---
FROM debian:bookworm-slim

# 仅安装基础运行时库
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从构建阶段拷贝编译好的程序
COPY --from=builder /app/baozap /app/baozap
# 拷贝默认配置文件（如果存在）
COPY config.json /app/config.json

# 启动程序
ENTRYPOINT ["/app/baozap"]