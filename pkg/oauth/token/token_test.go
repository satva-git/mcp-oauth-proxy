package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// fakeStore models the real store: a revoked token is rejected.
type fakeStore struct {
	mu     sync.Mutex
	tokens map[string]*types.TokenData // by refresh token
}

func (f *fakeStore) GetClient(string) (*types.ClientInfo, error)            { return nil, nil }
func (f *fakeStore) ValidateAuthCode(string) (string, string, error)        { return "", "", nil }
func (f *fakeStore) DeleteAuthCode(string) error                            { return nil }
func (f *fakeStore) GetGrant(string, string) (*types.Grant, error)         { return &types.Grant{}, nil }
func (f *fakeStore) StoreToken(t *types.TokenData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[t.RefreshToken] = t
	return nil
}
func (f *fakeStore) GetTokenByRefreshToken(rt string) (*types.TokenData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.tokens[rt]; ok && !t.Revoked {
		return t, nil
	}
	return nil, http.ErrNoCookie // any error: "not found"
}
func (f *fakeStore) RevokeToken(rt string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.tokens[rt]; ok {
		t.Revoked = true
	}
	return nil
}

func refresh(h *Handler, rt string) (int, types.TokenResponse) {
	form := url.Values{"refresh_token": {rt}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	w := httptest.NewRecorder()
	h.handleRefreshTokenGrant(w, r, "c1")
	var resp types.TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func TestConcurrentRefreshSharesOneRotation(t *testing.T) {
	st := &fakeStore{tokens: map[string]*types.TokenData{
		"u:g:old": {RefreshToken: "u:g:old", ClientID: "c1", UserID: "u", GrantID: "g",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour)},
	}}
	h := NewHandler(st).(*Handler)

	var wg sync.WaitGroup
	codes := make([]int, 5)
	rts := make([]string, 5)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, resp := refresh(h, "u:g:old")
			codes[i], rts[i] = c, resp.RefreshToken
		}(i)
	}
	wg.Wait()

	for i := range codes {
		if codes[i] != http.StatusOK {
			t.Fatalf("call %d got %d, want 200 (rotated-out token must be replayed)", i, codes[i])
		}
		if rts[i] != rts[0] {
			t.Fatalf("call %d got a different refresh token; rotations were not shared", i)
		}
	}
	// The new token still works for the next normal refresh.
	if c, _ := refresh(h, rts[0]); c != http.StatusOK {
		t.Fatalf("follow-up refresh with the new token got %d", c)
	}
}

func TestReplayIsClientScoped(t *testing.T) {
	st := &fakeStore{tokens: map[string]*types.TokenData{
		"u:g:old": {RefreshToken: "u:g:old", ClientID: "c1", UserID: "u", GrantID: "g",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour)},
	}}
	h := NewHandler(st).(*Handler)
	refresh(h, "u:g:old")

	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("refresh_token=u:g:old"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	w := httptest.NewRecorder()
	h.handleRefreshTokenGrant(w, r, "other-client")
	if w.Code == http.StatusOK {
		t.Fatal("a different client must not replay another client's rotation")
	}
}
