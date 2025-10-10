package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

type ScanRequestAPI struct {
	Domains  []string `json:"domains"`
	Keywords []string `json:"keywords,omitempty"`
	Ports    []int    `json:"ports,omitempty"`
}

type ScanResponseAPI struct {
	Success bool                             `json:"success"`
	Data    *domainscan.AssetDiscoveryResult `json:"data,omitempty"`
	Error   string                           `json:"error,omitempty"`
}

func main() {
	// Initialize scanner
	scanner := domainscan.New(domainscan.DefaultConfig())

	// Setup HTTP routes
	http.HandleFunc("/scan", handleScan(scanner))
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/", handleRoot)

	fmt.Println("🚀 Domain-scan API Server")
	fmt.Println("========================")
	fmt.Println("Listening on :8080")
	fmt.Println()
	fmt.Println("Endpoints:")
	fmt.Println("- POST /scan - Perform domain asset discovery")
	fmt.Println("- GET /health - Health check")
	fmt.Println()
	fmt.Println("Example request:")
	fmt.Println(`curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"], "keywords": ["staging"]}'`)

	// Example server - in production, use server with timeouts
	log.Fatal(http.ListenAndServe(":8080", nil)) // #nosec G114 - example code only
}

func handleScan(scanner *domainscan.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequestAPI
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if len(req.Domains) == 0 {
			sendErrorResponse(w, "No domains provided", http.StatusBadRequest)
			return
		}

		// Create scan request
		scanReq := &domainscan.ScanRequest{
			Domains:  req.Domains,
			Keywords: req.Keywords,
			Timeout:  10 * time.Second,
		}

		// Set default timeout if not specified
		if scanReq.Timeout == 0 {
			scanReq.Timeout = 10 * time.Second
		}

		// Set request timeout
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		// Perform scan
		result, err := scanner.ScanWithOptions(ctx, scanReq)
		if err != nil {
			sendErrorResponse(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Send response
		response := ScanResponseAPI{
			Success: true,
			Data:    result,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	docs := `
# Domain-scan API

A REST API for domain asset discovery.

## Endpoints

### POST /scan
Perform domain asset discovery.

**Request Body:**
{
  "domains": ["example.com"],
  "keywords": ["staging", "prod"],  // optional, combined with auto-extracted
  "ports": [80, 443, 8080]       // optional
}

**Response:**
{
  "success": true,
  "data": {
    "subdomains": [...],
    "active_services": [...],
    "statistics": {...}
  }
}

### GET /health
Health check endpoint.

## Usage Examples

### Basic scan
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'

### Scan with keywords
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"], "keywords": ["staging", "prod"]}'

### Custom scan
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com"],
    "keywords": ["staging", "prod"],
    "ports": [80, 443, 8080, 3000]
  }'
`

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(docs)); err != nil {
		http.Error(w, "Failed to write documentation", http.StatusInternalServerError)
	}
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := ScanResponseAPI{
		Success: false,
		Error:   message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}
