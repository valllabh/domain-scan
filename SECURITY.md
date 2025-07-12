# Security Policy

*This is a community-maintained open source project. Security support is provided on a best-effort basis.*

## Supported Versions

We actively support the following versions of domain-scan with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Considerations

### Intended Use
domain-scan is designed exclusively for **defensive security purposes** and authorized reconnaissance. It should only be used to assess systems and networks that you own or have explicit permission to test.

### Tool Classification
- **Passive reconnaissance tool** - Uses public data sources and standard protocols
- **Non-intrusive scanning** - Performs only basic HTTP requests and TLS handshakes
- **Rate-limited operations** - Respects target systems with built-in timeouts and concurrency limits

### Data Handling
- **No sensitive data storage** - Tool does not store or transmit sensitive information
- **Local execution only** - All scanning is performed locally on your system
- **Configurable output** - Results can be saved locally or streamed to stdout

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these guidelines:

### Where to Report
- **GitHub Security Advisories**: Use the "Security" tab in this repository for private disclosure
- **GitHub Issues**: For non-sensitive security questions and discussions

### What to Include
Please include the following information in your report:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if you have one)
5. **Your contact information** for follow-up

### Response Timeline
This is an open source project maintained on a best-effort basis:
- **Initial Response**: Within 1 week of receipt
- **Assessment**: Within 2-3 weeks depending on complexity
- **Fix Development**: Timeline varies based on severity and maintainer availability
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Classification

| Severity | Description | Best-Effort Response |
|----------|-------------|---------------------|
| **Critical** | Remote code execution, privilege escalation | 1-3 days |
| **High** | Significant security impact, data exposure | 1-2 weeks |
| **Medium** | Moderate security impact, limited exposure | 2-4 weeks |
| **Low** | Minor security issues, informational | 4-8 weeks |

*Note: As an open source project, response times depend on maintainer availability.*

## Security Best Practices for Users

### Installation Security
- **Verify checksums** of downloaded binaries against published SHA256 hashes
- **Use package managers** when available (Homebrew, APT, RPM) for automatic signature verification
- **Build from source** if you need to audit the code before use

### Operational Security
- **Use latest version** - Always run the most recent release for security patches
- **Limit scope** - Use keywords and port filters to minimize scanning footprint
- **Monitor resource usage** - Be aware of network and system resource consumption
- **Respect rate limits** - Use appropriate timeouts and concurrency settings

### Network Security
- **Authorized scanning only** - Only scan systems you own or have permission to test
- **Consider firewalls** - Be aware that scanning may trigger security monitoring
- **Use VPNs appropriately** - Consider your network source when scanning

## Dependency Security

### External Tools
domain-scan depends on these security tools:
- **subfinder** (ProjectDiscovery) - Passive subdomain enumeration
- **httpx** (ProjectDiscovery) - HTTP probing and TLS analysis

### Dependency Management
- Dependencies are automatically updated in CI/CD pipeline
- Security scanning is performed on all dependencies using `govulncheck`
- Known vulnerabilities are documented in `govulncheck.yaml` with risk assessments

### Vulnerability Exception Process
Some dependencies may have unfixable vulnerabilities. Our process:

1. **Risk Assessment** - Evaluate actual impact in our use case
2. **Documentation** - Record justification in `govulncheck.yaml`
3. **Monitoring** - Regular review of exceptions (every 6 months)
4. **Mitigation** - Implement workarounds where possible

## Secure Development Practices

### Code Security
- **Static analysis** with gosec for Go security patterns
- **Dependency scanning** with govulncheck for known vulnerabilities
- **Code review** requirements for all changes
- **Automated testing** including security test cases

### Build Security
- **Reproducible builds** using Go modules and locked dependencies
- **Multi-platform builds** in isolated CI/CD environments
- **Signed releases** with checksums for integrity verification
- **Minimal attack surface** with statically linked binaries

### CI/CD Security
- **Branch protection** on main branch
- **Required status checks** including security scans
- **Secrets management** using GitHub encrypted secrets
- **Automated security updates** via Dependabot

## Security Scanning Results

### Current Status
- **Static Analysis**: ✅ No security issues (gosec)
- **Dependency Scan**: ✅ No actionable vulnerabilities (govulncheck with documented exceptions)
- **Code Quality**: ✅ All linters passing

### Regular Scans
Security scans are performed:
- **On every pull request** - Automated CI/CD pipeline
- **Weekly** - Scheduled dependency vulnerability checks
- **Before releases** - Comprehensive security review

## Compliance and Standards

### Security Standards
- **OWASP Secure Coding Practices**
- **NIST Cybersecurity Framework** alignment
- **CIS Controls** for secure development

### Privacy Considerations
- **No telemetry** - Tool does not send usage data
- **Local processing** - All operations performed locally
- **Configurable logging** - Users control what information is logged

## Contact Information

### Security Reporting
- **GitHub Security Advisories**: Primary method for vulnerability reports
- **GitHub Issues**: For general security questions and discussions

### Community Support
- **GitHub Issues**: For general security questions (non-sensitive)
- **GitHub Discussions**: For security best practices and usage questions
- **Documentation**: See README.md and CLAUDE.md for operational security guidance

*Note: This is a community-maintained open source project. Security responses are provided on a best-effort basis.*

---

**Note**: This security policy applies to the domain-scan project. For security issues in dependencies (subfinder, httpx), please report directly to ProjectDiscovery through their security channels.

Last updated: January 2025