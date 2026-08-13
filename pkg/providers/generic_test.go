package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericProvider_RefreshTokenParams(t *testing.T) {
	t.Run("TestGoogleRefreshTokenParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "openid profile email", "test_state")

		assert.Contains(t, authURL, "access_type=offline")
		assert.Contains(t, authURL, "prompt=consent")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=openid+profile+email")
		assert.Contains(t, authURL, "state=test_state")
	})

	t.Run("TestGenericProviderNoSpecialParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://github.com/login/oauth/authorize",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "read:user user:email", "test_state")

		// Should not contain Google or Microsoft specific parameters
		assert.NotContains(t, authURL, "response_mode=query")
		assert.NotContains(t, authURL, "offline_access")

		// Should contain standard OAuth parameters
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=read%3Auser+user%3Aemail")
		assert.Contains(t, authURL, "state=test_state")
	})
}

// TestGenericProvider_EndpointOverrides verifies that token/userinfo URL
// overrides bypass OIDC discovery entirely when both are set, so non-OIDC
// providers (e.g. 37signals Basecamp) work without a /.well-known/* document.
func TestGenericProvider_EndpointOverrides(t *testing.T) {
	provider := NewGenericProviderWithOverrides(
		"https://launchpad.37signals.com/authorization/new",
		"https://launchpad.37signals.com/authorization/token",
		"https://launchpad.37signals.com/authorization.json",
	)
	require.NoError(t, provider.discoverEndpoints())
	assert.Equal(t, "https://launchpad.37signals.com/authorization/token", provider.metadata.TokenEndpoint)
	assert.Equal(t, "https://launchpad.37signals.com/authorization.json", provider.metadata.UserinfoEndpoint)
	assert.Equal(t, "https://launchpad.37signals.com/authorization/new", provider.metadata.AuthorizationEndpoint)
}

// TestGenericProvider_BasecampIdentityShape verifies that GetUserInfo can parse
// 37signals Basecamp's nested {"identity": {...}} response shape.
func TestGenericProvider_BasecampIdentityShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"identity": map[string]any{
				"id":            float64(12345678),
				"email_address": "user@example.com",
				"first_name":    "Ada",
				"last_name":     "Lovelace",
			},
			"accounts": []any{},
		})
	}))
	defer srv.Close()

	provider := NewGenericProviderWithOverrides(
		"https://launchpad.37signals.com/authorization/new",
		srv.URL+"/token",
		srv.URL,
	)

	ui, err := provider.GetUserInfo(context.Background(), "fake-token")
	require.NoError(t, err)
	assert.Equal(t, "12345678", ui.ID)
	assert.Equal(t, "user@example.com", ui.Email)
	assert.Equal(t, "Ada", ui.GivenName)
	assert.Equal(t, "Lovelace", ui.FamilyName)
	assert.Equal(t, "Ada Lovelace", ui.Name)
}

// TestGenericProvider_BackwardsCompatibleFlatShape ensures the original
// flat OIDC parsing still works when no identity sub-object is present.
func TestGenericProvider_BackwardsCompatibleFlatShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":   "google-user-id",
			"email": "g@example.com",
			"name":  "G User",
		})
	}))
	defer srv.Close()

	provider := NewGenericProviderWithOverrides(
		"https://accounts.google.com/o/oauth2/v2/auth",
		srv.URL+"/token",
		srv.URL,
	)
	ui, err := provider.GetUserInfo(context.Background(), "fake")
	require.NoError(t, err)
	assert.Equal(t, "google-user-id", ui.ID)
	assert.Equal(t, "g@example.com", ui.Email)
	assert.Equal(t, "G User", ui.Name)
}

// TestGenericProvider_PromptSuppressesApprovalPrompt verifies that configuring an
// explicit "prompt" via OAUTH_EXTRA_AUTHORIZE_PARAMS replaces oauth2.ApprovalForce
// (itself prompt=consent) rather than emitting the prompt parameter twice.
func TestGenericProvider_PromptSuppressesApprovalPrompt(t *testing.T) {
	provider := NewGenericProvider("https://accounts.google.com/o/oauth2/v2/auth")
	require.NoError(t, provider.SetExtraParams("prompt=select_account+consent", ""))

	raw := provider.GetAuthorizationURLWithPKCE("cid", "https://x.example/callback", "openid", "state", "")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()

	assert.Equal(t, []string{"select_account consent"}, q["prompt"],
		"prompt must appear exactly once, with the configured value")
	assert.Equal(t, "offline", q.Get("access_type"))
}

// TestGenericProvider_DefaultKeepsConsentPrompt ensures the default
// consent-forcing behaviour is unchanged when no explicit prompt is configured.
func TestGenericProvider_DefaultKeepsConsentPrompt(t *testing.T) {
	provider := NewGenericProvider("https://accounts.google.com/o/oauth2/v2/auth")

	raw := provider.GetAuthorizationURLWithPKCE("cid", "https://x.example/callback", "openid", "state", "")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()

	assert.Equal(t, []string{"consent"}, q["prompt"])
}
