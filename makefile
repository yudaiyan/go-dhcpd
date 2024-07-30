.PHONY: all
all: build

.PHONY: build
build: 
	# 编译
	go mod tidy
	GOEXPERIMENT=rangefunc go build -v ./...
	GOOS=windows GOARCH=amd64 GOEXPERIMENT=rangefunc go build -v ./...