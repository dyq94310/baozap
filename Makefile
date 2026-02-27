# 变量定义
BINARY_NAME=baozap
REMOTE_DEST=~/bao/
GO_BIN ?= $(shell which go)
GO_BIN := $(if $(GO_BIN),$(GO_BIN),/usr/local/go/bin/go)
GOCACHE ?= /tmp/go-build-cache
GOMODCACHE ?= $(HOME)/go/pkg/mod
# 定义目标机器列表
# TARGET_HOSTS=rich ix
TARGET_HOSTS=rich
# TARGET_HOSTS=ix


.PHONY: all build test test-xdp gen-bpf stop deploy start clean

# 默认执行流程
all: build stop deploy start

# 生成 eBPF 相关代码与对象文件
gen-bpf:
	@echo ">> Generating XDP bytecodes..."
	$(GO_BIN) generate ./...

# 1. 编译构建 (包含 go generate 处理 XDP 字节码)
build: gen-bpf
	@echo ">> Building Go binary..."
	GOOS=linux GOARCH=amd64 $(GO_BIN) build -o $(BINARY_NAME) .

# 常规测试（不依赖 root）
test: gen-bpf
	@echo ">> Running tests..."
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO_BIN) test ./...

# XDP 集成测试（依赖 root/CAP_BPF）
test-xdp: gen-bpf
	@echo ">> Running XDP integration tests..."
	mkdir -p $(GOCACHE)
	sudo --preserve-env=HTTP_PROXY,HTTPS_PROXY,NO_PROXY,http_proxy,https_proxy,no_proxy \
		GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) \
		$(GO_BIN) test ./test -run TestXDPForwardAndReverseRewrite -v

# 2. 停止远程服务
stop:
	@for host in $(TARGET_HOSTS); do \
		echo ">> Stopping service on $$host..."; \
		ssh $$host "bash $(REMOTE_DEST)stop.sh" || echo "Stop script failed on $$host, continuing..."; \
	done

# 3. 拷贝二进制文件
deploy: build
	@for host in $(TARGET_HOSTS); do \
		echo ">> Deploying to $$host..."; \
		scp $(BINARY_NAME) $$host:$(REMOTE_DEST); \
	done

# 4. 启动远程服务
start:
	@for host in $(TARGET_HOSTS); do \
		echo ">> Starting service on $$host..."; \
		ssh -f $$host "bash $(REMOTE_DEST)start.sh"; \
	done

# 清理本地二进制
clean:
	rm -f $(BINARY_NAME)
