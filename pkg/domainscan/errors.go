package domainscan

import "fmt"

// DomainScanError represents errors that can occur during domain scanning
type DomainScanError struct {
	Code    ErrorCode
	Message string
	Err     error
}

// ErrorCode represents different types of errors
type ErrorCode int

const (
	// ErrInvalidConfig indicates invalid configuration
	ErrInvalidConfig ErrorCode = iota
	// ErrDependencyMissing indicates a required dependency is missing
	ErrDependencyMissing
	// ErrPassiveDiscoveryFailed indicates passive discovery failed
	ErrPassiveDiscoveryFailed
	// ErrCertificateAnalysisFailed indicates certificate analysis failed
	ErrCertificateAnalysisFailed
	// ErrHTTPScanFailed indicates HTTP scanning failed
	ErrHTTPScanFailed
	// ErrTimeout indicates the operation timed out
	ErrTimeout
	// ErrNetworkError indicates a network-related error
	ErrNetworkError
)

// Error implements the error interface
func (e *DomainScanError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *DomainScanError) Unwrap() error {
	return e.Err
}

// NewError creates a new DomainScanError
func NewError(code ErrorCode, message string, err error) *DomainScanError {
	return &DomainScanError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// String returns a string representation of the error code
func (ec ErrorCode) String() string {
	switch ec {
	case ErrInvalidConfig:
		return "InvalidConfig"
	case ErrDependencyMissing:
		return "DependencyMissing"
	case ErrPassiveDiscoveryFailed:
		return "PassiveDiscoveryFailed"
	case ErrCertificateAnalysisFailed:
		return "CertificateAnalysisFailed"
	case ErrHTTPScanFailed:
		return "HTTPScanFailed"
	case ErrTimeout:
		return "Timeout"
	case ErrNetworkError:
		return "NetworkError"
	default:
		return "Unknown"
	}
}
