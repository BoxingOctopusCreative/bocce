APP_NAME := bocce
DIST_DIR := dist
MAIN_PKG := .
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: test build clean build-macos build-linux build-all

test:
	go test ./...

build:
	go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) $(MAIN_PKG)

build-macos-arm64:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_PKG)

build-macos-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_PKG)

build-macos:
	$(MAKE) build-macos-arm64 build-macos-amd64

build-linux-arm64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PKG)

build-linux-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PKG)

build-linux:
	$(MAKE) build-linux-arm64 build-linux-amd64

build-windows:
	mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN_PKG)

build-all: build-macos build-linux build-windows

clean:
	rm -rf $(DIST_DIR)
