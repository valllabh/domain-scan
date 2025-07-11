# Build stage
FROM golang:1.24-alpine AS builder

# Set build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o domain-scan ./main_new.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S domain-scan && \
    adduser -u 1001 -S domain-scan -G domain-scan

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/domain-scan .

# Copy configuration
COPY --from=builder /build/config.yaml .

# Set ownership
RUN chown -R domain-scan:domain-scan /app

# Switch to non-root user
USER domain-scan

# Expose any ports if needed (none for this CLI tool)
# EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["./domain-scan"]

# Default command
CMD ["--help"]