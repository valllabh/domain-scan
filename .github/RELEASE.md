# Release Process

This document describes the automated release process for domain-scan using GitHub Actions and GoReleaser.

## Overview

The project uses GoReleaser to automate:
- Cross-platform binary builds (Linux, macOS, Windows)
- Package creation (DEB, RPM, APK)
- Docker image builds (multi-architecture)
- Homebrew formula updates
- GitHub release creation

## Workflows

### 1. Release Workflow (`.github/workflows/release.yml`)

**Trigger**: When a new tag matching `v*` is pushed

**What it does**:
- Runs all tests
- Builds binaries for multiple platforms
- Creates packages (DEB, RPM, APK)
- Builds and pushes Docker images to GHCR
- Creates GitHub release with changelog
- Updates Homebrew tap (if configured)

### 2. CI Workflow (`.github/workflows/ci.yml`)

**Trigger**: On push to main/develop branches and pull requests

**What it does**:
- Tests across multiple Go versions and OS platforms
- Runs linting and security checks
- Creates snapshot builds
- Uploads coverage reports

### 3. Docker Workflow (`.github/workflows/docker.yml`)

**Trigger**: On push to main branch and tags

**What it does**:
- Builds multi-architecture Docker images
- Pushes to GitHub Container Registry (GHCR)
- Tags images appropriately

### 4. CodeQL Workflow (`.github/workflows/codeql.yml`)

**Trigger**: On push, pull requests, and weekly schedule

**What it does**:
- Performs security analysis
- Scans for vulnerabilities

## Creating a Release

### Automatic Release (Recommended)

1. **Ensure all changes are merged to main branch**
2. **Create and push a new tag**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. **Monitor the release workflow** in GitHub Actions
4. **Verify the release** was created successfully

### Manual Release (Testing)

Use the test-release workflow for validation:

1. Go to Actions → Test Release
2. Click "Run workflow"
3. Set dry_run to true for testing
4. Check the generated artifacts

## Release Artifacts

Each release produces:

### Binaries
- `domain-scan_Darwin_arm64.tar.gz` - macOS Apple Silicon
- `domain-scan_Darwin_x86_64.tar.gz` - macOS Intel
- `domain-scan_Linux_arm64.tar.gz` - Linux ARM64
- `domain-scan_Linux_x86_64.tar.gz` - Linux x86_64
- `domain-scan_Windows_x86_64.zip` - Windows x86_64

### Packages
- `domain-scan_amd64.deb` - Debian/Ubuntu package
- `domain-scan_amd64.rpm` - RHEL/CentOS/Fedora package
- `domain-scan_amd64.apk` - Alpine Linux package

### Docker Images
- `ghcr.io/domain-scan/domain-scan:v1.0.0` - Versioned image
- `ghcr.io/domain-scan/domain-scan:latest` - Latest image
- Available for both amd64 and arm64 architectures

### Checksums
- `checksums.txt` - SHA256 checksums for all artifacts

## Configuration

### Required Secrets

The workflows require these GitHub secrets:

- `GITHUB_TOKEN` - Automatically provided by GitHub
- `HOMEBREW_TAP_GITHUB_TOKEN` - Personal access token for Homebrew tap updates

### Optional Secrets

- `DOCKER_USERNAME` / `DOCKER_PASSWORD` - If using Docker Hub
- `CODECOV_TOKEN` - For enhanced coverage reporting

## Versioning

The project follows [Semantic Versioning](https://semver.org/):

- `v1.0.0` - Major release
- `v1.1.0` - Minor release (new features)
- `v1.1.1` - Patch release (bug fixes)

## Troubleshooting

### Build Failures

1. **Check test results** - Builds fail if tests don't pass
2. **Verify Go version** - Ensure compatibility with Go 1.21+
3. **Check dependencies** - Ensure all dependencies are available

### Docker Build Issues

1. **Check Dockerfile** - Ensure it's valid and builds locally
2. **Verify base images** - Ensure base images are accessible
3. **Check registry permissions** - Ensure GHCR access is configured

### Homebrew Issues

1. **Check tap repository** - Ensure homebrew-tap repository exists
2. **Verify token permissions** - Ensure HOMEBREW_TAP_GITHUB_TOKEN has write access
3. **Check formula template** - Ensure GoReleaser Homebrew config is correct

## Manual Testing

Before creating a release, you can test locally:

```bash
# Test GoReleaser configuration
goreleaser check

# Create a snapshot build
goreleaser release --snapshot --clean

# Test Docker build
docker build -t domain-scan:test .

# Run tests
go test -v ./...
```

## Post-Release

After a successful release:

1. **Test the release artifacts** on different platforms
2. **Update documentation** if needed
3. **Announce the release** in relevant channels
4. **Monitor for issues** and prepare hotfixes if needed