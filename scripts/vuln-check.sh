#!/bin/bash
# Vulnerability checker with exceptions support
# Filters out documented exceptions from govulncheck output

set -e

echo "🔍 Checking for actionable vulnerabilities..."
echo "📋 Documented exceptions are listed in govulncheck.yaml"
echo ""

# Run govulncheck and capture output
if ! output=$(govulncheck ./... 2>&1); then
    # govulncheck found vulnerabilities, let's filter them
    echo "$output" | head -n 20  # Show first part of output for context
    
    # Check if the only vulnerability is our known exception
    if echo "$output" | grep -q "GO-2024-2698" && \
       echo "$output" | grep -q "github.com/mholt/archiver" && \
       ! echo "$output" | grep -q "Vulnerability #2:"; then
        echo ""
        echo "✅ No actionable vulnerabilities found!"
        echo "   (Excluding documented exception: GO-2024-2698 - archiver path traversal)"
        echo ""
        echo "📝 To see all vulnerabilities including exceptions: make vuln-all"
        exit 0
    else
        echo ""
        echo "❌ Found actionable vulnerabilities that need attention!"
        echo "   Please review and fix the vulnerabilities above."
        exit 1
    fi
else
    echo "✅ No vulnerabilities found!"
    exit 0
fi