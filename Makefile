# 变量定义
BINARY_NAME=baozap
REMOTE_DEST=~/bao/
# 定义目标机器列表
# TARGET_HOSTS=rich ix
TARGET_HOSTS=rich
# TARGET_HOSTS=ix


.PHONY: all build stop deploy start clean

# 默认执行流程
all: build stop deploy start

# 1. 编译构建 (包含 go generate 处理 XDP 字节码)
build:
	@echo ">> Generating XDP bytecodes..."
	go generate ./...
	@echo ">> Building Go binary..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) .

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
