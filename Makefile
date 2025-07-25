# Makefile for domain-scan

# Build variables
BINARY_NAME=domain-scan
MAIN_FILE=main_new.go
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD)
DATE=$(shell date +%Y-%m-%dT%H:%M:%S%z)
LDFLAGS=-ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Directories
BUILD_DIR=build
DIST_DIR=dist

.PHONY: all build clean test deps fmt lint install uninstall release snapshot help

# Default target
all: clean fmt test build

# Build the binary
build:
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p ${BUILD_DIR}
	# Linux AMD64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${MAIN_FILE}
	# Linux ARM64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64 ${MAIN_FILE}
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64 ${MAIN_FILE}
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64 ${MAIN_FILE}
	# Windows AMD64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe ${MAIN_FILE}

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	$(GOMOD) verify

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

# Lint code
lint:
	@echo "Linting code..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf ${BUILD_DIR}
	rm -rf ${DIST_DIR}
	rm -f coverage.out coverage.html

# Install binary to GOPATH/bin
install: build
	@echo "Installing ${BINARY_NAME} to ${GOPATH}/bin..."
	cp ${BUILD_DIR}/${BINARY_NAME} ${GOPATH}/bin/

# Uninstall binary from GOPATH/bin
uninstall:
	@echo "Uninstalling ${BINARY_NAME} from ${GOPATH}/bin..."
	rm -f ${GOPATH}/bin/${BINARY_NAME}

# Run the application with arguments
# Usage: make run ARGS="discover example.com --keywords staging,prod"
run:
	@echo "Running ${BINARY_NAME} with args: $(ARGS)"
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}
	./${BUILD_DIR}/${BINARY_NAME} $(ARGS)

# Quick run shortcuts for common development tasks
run-help:
	@echo "Running ${BINARY_NAME} --help..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}
	./${BUILD_DIR}/${BINARY_NAME} --help

run-discover:
	@echo "Running discover command with example.com..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}
	./${BUILD_DIR}/${BINARY_NAME} discover example.com --keywords staging,prod

run-config:
	@echo "Running config command..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}
	./${BUILD_DIR}/${BINARY_NAME} config


# Development build (no optimization)
dev:
	@echo "Building development version..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) -race -o ${BUILD_DIR}/${BINARY_NAME}-dev ${MAIN_FILE}

# Release using GoReleaser
release:
	@echo "Creating release..."
	@which goreleaser > /dev/null || (echo "Installing goreleaser..." && go install github.com/goreleaser/goreleaser@latest)
	goreleaser release --clean

# Create snapshot release
snapshot:
	@echo "Creating snapshot release..."
	@which goreleaser > /dev/null || (echo "Installing goreleaser..." && go install github.com/goreleaser/goreleaser@latest)
	goreleaser release --snapshot --clean


# Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	./${BUILD_DIR}/${BINARY_NAME} discover --help > docs/discover.md
	./${BUILD_DIR}/${BINARY_NAME} config --help > docs/config.md

# Initialize development environment
init:
	@echo "Initializing development environment..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/goreleaser/goreleaser@latest
	@echo "Development environment ready!"

# Benchmark tests
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Security scan
security:
	@echo "Running security scan..."
	@echo "Installing/updating latest gosec..."
	@curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
	gosec ./...

# Vulnerability check (shows all vulnerabilities including accepted ones)
vuln:
	@echo "Checking for vulnerabilities..."
	@echo "Installing/updating latest govulncheck..."
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# Vulnerability check with exceptions (filtered for actionable vulnerabilities only)
vuln-check:
	@echo "Installing/updating latest govulncheck..."
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@./scripts/vuln-check.sh

# Show all vulnerabilities including exceptions (alias for vuln)
vuln-all: vuln

# Update dependencies
update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Install dependencies"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  install       - Install binary to GOPATH/bin"
	@echo "  uninstall     - Uninstall binary from GOPATH/bin"
	@echo "  run           - Build and run the application (use ARGS='...' to pass arguments)"
	@echo "  run-help      - Run application with --help"
	@echo "  run-discover  - Run quick discovery on example.com"
	@echo "  run-config    - Run config command"
	@echo "  dev           - Build development version"
	@echo "  release       - Create release using GoReleaser"
	@echo "  snapshot      - Create snapshot release"
	@echo "  docs          - Generate documentation"
	@echo "  init          - Initialize development environment"
	@echo "  bench         - Run benchmark tests"
	@echo "  security      - Run security scan"
	@echo "  vuln          - Check for vulnerabilities (shows all)"
	@echo "  vuln-check    - Check for actionable vulnerabilities (excludes documented exceptions)"
	@echo "  vuln-all      - Show all vulnerabilities including exceptions"
	@echo "  update        - Update dependencies"
	@echo "  help          - Show this help message"