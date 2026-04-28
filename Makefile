APP_NAME := do-user-data-render
DIST_DIR := dist
MAIN_PKG := .

.PHONY: build clean build-macos build-linux build-all

build:
	go build -o $(DIST_DIR)/$(APP_NAME) $(MAIN_PKG)

build-macos:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 go build -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_PKG)
	GOOS=darwin GOARCH=amd64 go build -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_PKG)

build-linux:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 go build -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PKG)
	GOOS=linux GOARCH=amd64 go build -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PKG)

build-all: build-macos build-linux

clean:
	rm -rf $(DIST_DIR)
