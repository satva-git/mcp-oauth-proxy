package handlerutils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// CachedJSON writes obj as JSON with a strong ETag and a Cache-Control max-age
// (in seconds). It is meant for responses whose body is static for the lifetime
// of the process (e.g. OAuth discovery metadata). When the request carries a
// matching If-None-Match header it short-circuits with 304 Not Modified.
//
// Why this exists: OAuth clients (notably the obot gateway) re-fetch the
// /.well-known/* discovery documents very frequently. Without cache headers the
// proxy answered 200 every time, which on the obot side triggered repeated
// "Updated MCP server OAuth metadata" cycles and dynamic-client rotation,
// orphaning tokens. Advertising cacheability lets well-behaved clients skip the
// re-fetch and reduces that churn.
func CachedJSON(w http.ResponseWriter, r *http.Request, statusCode, maxAgeSeconds int, obj any) {
	body, err := json.Marshal(obj)
	if err != nil {
		JSON(w, statusCode, obj) // fall back to the uncached encoder, which handles the error
		return
	}

	sum := sha256.Sum256(body)
	etag := fmt.Sprintf("%q", hex.EncodeToString(sum[:]))

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAgeSeconds))
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(body); err != nil {
		log.Printf("Error writing JSON response: %v", err)
	}
}

// etagMatches reports whether the (possibly comma-separated, possibly weak)
// If-None-Match header contains etag. A "*" always matches.
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

func JSON(w http.ResponseWriter, statusCode int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if obj != nil {
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			// Write error response if encoding fails
			errText, _ := json.Marshal(map[string]string{
				"error":             "internal_server_error",
				"error_description": "Failed to encode JSON response",
				"error_detail":      err.Error(),
			})
			_, _ = w.Write(errText)
		}
	}
}

// GetClientIP extracts the client IP from the request using the X-Forwarded-For,
// X-Real-IP and RemoteAddr headers.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Get the first IP in the comma-separated list
		ifs := strings.Split(xff, ",")
		return strings.TrimSpace(ifs[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	return ip
}

// GetBaseURL returns the URL of the request without the path and
// infers the scheme (http or https)
func GetBaseURL(r *http.Request) string {
	if url := r.Header.Get("X-Mcp-Oauth-Proxy-URL"); url != "" {
		return url
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}
