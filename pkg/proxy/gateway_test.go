package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// newProxyWithGateway builds a bare proxy carrying only the gateway config the
// middleware reads. The middleware touches nothing else, so no DB is needed.
func newProxyWithGateway(secret, header string) *OAuthProxy {
	return &OAuthProxy{config: &types.Config{GatewaySecret: secret, GatewayHeaderName: header}}
}

func runGate(p *OAuthProxy, header, value string) *httptest.ResponseRecorder {
	reached := false
	h := p.withGatewaySecret(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp/google-drive/", nil)
	if header != "" {
		req.Header.Set(header, value)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	// stash whether the inner handler ran, for assertions
	if reached {
		rec.Header().Set("X-Test-Reached", "1")
	}
	return rec
}

func TestGatewaySecret(t *testing.T) {
	const secret = "s3cr3t-gateway-value"

	t.Run("disabled when secret empty lets everything through", func(t *testing.T) {
		rec := runGate(newProxyWithGateway("", "X-Satva-Gateway"), "", "")
		if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Reached") != "1" {
			t.Fatalf("expected pass-through, got code=%d reached=%q", rec.Code, rec.Header().Get("X-Test-Reached"))
		}
	})

	t.Run("correct header passes", func(t *testing.T) {
		rec := runGate(newProxyWithGateway(secret, "X-Satva-Gateway"), "X-Satva-Gateway", secret)
		if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Reached") != "1" {
			t.Fatalf("expected pass, got code=%d reached=%q", rec.Code, rec.Header().Get("X-Test-Reached"))
		}
	})

	t.Run("wrong value is refused with 403 and never reaches handler", func(t *testing.T) {
		rec := runGate(newProxyWithGateway(secret, "X-Satva-Gateway"), "X-Satva-Gateway", "not-the-secret")
		if rec.Code != http.StatusForbidden || rec.Header().Get("X-Test-Reached") == "1" {
			t.Fatalf("expected 403 and no handler, got code=%d reached=%q", rec.Code, rec.Header().Get("X-Test-Reached"))
		}
	})

	t.Run("missing header is refused with 403", func(t *testing.T) {
		rec := runGate(newProxyWithGateway(secret, "X-Satva-Gateway"), "", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("empty header name falls back to default, still enforces", func(t *testing.T) {
		// GatewayHeaderName unset must NOT lock the gateway out: it falls back to
		// X-Satva-Gateway, so the correct header on that name passes...
		rec := runGate(newProxyWithGateway(secret, ""), "X-Satva-Gateway", secret)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected fallback header to pass, got %d", rec.Code)
		}
		// ...and a request with no header is still refused.
		rec = runGate(newProxyWithGateway(secret, ""), "", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 with no header, got %d", rec.Code)
		}
	})

	t.Run("custom header name is honored", func(t *testing.T) {
		rec := runGate(newProxyWithGateway(secret, "X-Custom-Gate"), "X-Custom-Gate", secret)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected custom header to pass, got %d", rec.Code)
		}
	})
}
