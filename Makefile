# 变量定义
BINARY_NAME=baozap
GO_BIN ?= $(shell which go)
GO_BIN := $(if $(GO_BIN),$(GO_BIN),/usr/local/go/bin/go)
GOCACHE ?= /tmp/go-build-cache
GOMODCACHE ?= $(HOME)/go/pkg/mod


.PHONY: all build test test-go test-xdp gen-bpf clean

# 默认执行流程
all: build

# 生成 eBPF 相关代码与对象文件
gen-bpf:
	@echo ">> Generating XDP bytecodes..."
	$(GO_BIN) generate ./...

# 1. 编译构建 (包含 go generate 处理 XDP 字节码)
build: gen-bpf
	@echo ">> Building Go binary..."
	GOOS=linux GOARCH=amd64 $(GO_BIN) build -o $(BINARY_NAME) .

# 常规测试（不依赖 root）
test-go: gen-bpf
	@echo ">> Running tests..."
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO_BIN) test ./...

# 完整测试（Go 单测 + XDP 集成测试）
test: test-go test-xdp

# XDP 集成测试（依赖 root/CAP_BPF）
test-xdp: gen-bpf
	@echo ">> Running XDP integration tests..."
	mkdir -p $(GOCACHE)
	sudo --preserve-env=HTTP_PROXY,HTTPS_PROXY,NO_PROXY,http_proxy,https_proxy,no_proxy \
		GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) \
		$(GO_BIN) test ./test -tags xdp_integration -run TestXDP -v

# 清理本地二进制
clean:
	rm -f $(BINARY_NAME)
