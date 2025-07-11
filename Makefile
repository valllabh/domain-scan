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

.PHONY: all build clean test deps fmt lint install uninstall release snapshot docker help

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

# Run the application
run:
	@echo "Running ${BINARY_NAME}..."
	$(GOBUILD) $(LDFLAGS) -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_FILE}
	./${BUILD_DIR}/${BINARY_NAME}

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

# Docker build
docker:
	@echo "Building Docker image..."
	docker build -t ${BINARY_NAME}:${VERSION} .
	docker build -t ${BINARY_NAME}:latest .

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run --rm -it ${BINARY_NAME}:latest

# Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	./${BUILD_DIR}/${BINARY_NAME} discover --help > docs/discover.md
	./${BUILD_DIR}/${BINARY_NAME} config --help > docs/config.md
	./${BUILD_DIR}/${BINARY_NAME} install --help > docs/install.md

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
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)
	gosec ./...

# Vulnerability check
vuln:
	@echo "Checking for vulnerabilities..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

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
	@echo "  run           - Build and run the application"
	@echo "  dev           - Build development version"
	@echo "  release       - Create release using GoReleaser"
	@echo "  snapshot      - Create snapshot release"
	@echo "  docker        - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  docs          - Generate documentation"
	@echo "  init          - Initialize development environment"
	@echo "  bench         - Run benchmark tests"
	@echo "  security      - Run security scan"
	@echo "  vuln          - Check for vulnerabilities"
	@echo "  update        - Update dependencies"
	@echo "  help          - Show this help message"