.PHONY: build run test clean coverage lint

BINARY_NAME=xsscan
GO=go
GOBUILD=$(GO) build
GOTEST=$(GO) test
GOCLEAN=$(GO) clean
GOMOD=$(GO) mod

VERSION ?= 0.9.7
LDFLAGS = -X main.Version=$(VERSION)

build:
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd

run: build
	./$(BINARY_NAME)

test:
	$(GOTEST) -race ./...

coverage:
	$(GOTEST) -race -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html

coverage-scanner:
	$(GOTEST) -race -cover -coverprofile=scanner.out ./pkg/scanner/
	go tool cover -func=scanner.out

coverage-cli:
	$(GOTEST) -race -cover -coverprofile=cli.out ./cmd/
	go tool cover -func=cli.out

lint:
	go vet ./...

deps:
	$(GOMOD) download
	$(GOMOD) tidy

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) coverage.out coverage.html scanner.out cli.out

dev:
	$(GO) run ./cmd

.DEFAULT_GOAL := build
