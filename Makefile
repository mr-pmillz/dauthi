BIN="./bin"
SRC=$(shell find . -name "*.go")
CURRENT_TAG=$(shell git describe --tags --abbrev=0)

GOLANGCI := $(shell command -v golangci-lint 2>/dev/null)

.PHONY: fmt lint build clean compile compress

default: all

all: fmt lint build release

release: clean build compile compress

fmt:
	$(info ******************** checking formatting ********************)
	@test -z $(shell gofmt -l $(SRC)) || (gofmt -d $(SRC); exit 1)

.PHONY: golangci-lint-check
golangci-lint-check:
ifndef GITHUB_ACTIONS
	$(info ******************** checking if golangci-lint is installed ********************)
	$(warning "ensuring latest version of golangci-lint installed, running: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest")
	go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@latest
endif

.PHONY: lint
lint: golangci-lint-check
	$(info ******************** running lint tools ********************)
	golangci-lint run -c .golangci-lint.yml -v ./... --timeout 10m

changelog:
	$(info ******************** running git-cliff updating CHANGELOG.md ********************)
	git-cliff -o CHANGELOG.md

clean:
	rm -rf $(BIN) 2>/dev/null

build:
	go env -w GOFLAGS=-mod=mod
	go mod tidy
	go build -v -trimpath -ldflags="-s -w" .

compile:
	GOOS=linux GOARCH=amd64 go build -o bin/linux/amd64/dauthi-$(CURRENT_TAG)-linux-amd64 -trimpath -ldflags="-s -w" main.go
	GOOS=linux GOARCH=arm64 go build -o bin/linux/arm64/dauthi-$(CURRENT_TAG)-linux-arm64 -trimpath -ldflags="-s -w" main.go
	GOOS=darwin GOARCH=amd64 go build -o bin/darwin/amd64/dauthi-$(CURRENT_TAG)-x86_64-macos-darwin_amd64 -trimpath -ldflags="-s -w" main.go
	GOOS=darwin GOARCH=arm64 go build -o bin/darwin/arm64/dauthi-$(CURRENT_TAG)-x86_64-macos-darwin_arm64 -trimpath -ldflags="-s -w" main.go

compress:
	gzip -9 bin/linux/amd64/dauthi-$(CURRENT_TAG)-linux-amd64
	gzip -9 bin/linux/arm64/dauthi-$(CURRENT_TAG)-linux-arm64
	gzip -9 bin/darwin/amd64/dauthi-$(CURRENT_TAG)-x86_64-macos-darwin_amd64
	gzip -9 bin/darwin/arm64/dauthi-$(CURRENT_TAG)-x86_64-macos-darwin_arm64
