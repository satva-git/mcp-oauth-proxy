package types

import (
	"time"
)

const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
)

// Config holds all configuration values for the OAuth proxy
type Config struct {
	Port              string
	DatabaseDSN       string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthAuthorizeURL string
	OAuthJWKSURL      string
	TrustedIssuer     string
	TrustedAudiences  []string
	OAuthTokenURL     string
	OAuthUserinfoURL  string
	// Extra query-string parameters appended verbatim to the authorize URL
	// (e.g. "type=web_server" for 37signals Basecamp). Format: URL-encoded
	// query string (a=1&b=2). Empty means no extra params.
	OAuthExtraAuthorizeParams string
	// Extra parameters added to the token-exchange POST body (e.g.
	// "type=web_server" for 37signals Basecamp). Same format as above.
	OAuthExtraTokenParams string
	ScopesSupported       string
	EncryptionKey         string
	MCPServerURL          string
	Mode                  string
	RoutePrefix           string
	CookieNamePrefix      string
	MCPPaths              []string
	// AllowedEmailDomains restricts which identities may complete the OAuth
	// flow. Empty means any account is accepted.
	AllowedEmailDomains []string
	// GatewaySecret, when non-empty, requires every request to the MCP proxy
	// route (NOT the OAuth routes) to carry GatewayHeaderName equal to this
	// value. O-Bot injects it as a fixed header from its catalog entry; a
	// direct client (mcp-remote, Cursor, Claude Desktop) has no way to send it
	// and is refused with 403. Empty means the gate is off (deploy-before-O-Bot
	// state). The OAuth endpoints stay open because the browser redirect that
	// hits /authorize and /callback cannot carry a custom header.
	GatewaySecret     string
	GatewayHeaderName string

	APIKeyAuthWebhookURL string
	MCPServerID          string
}

// TokenData represents stored token data for OAuth 2.1 compliance
type TokenData struct {
	AccessToken           string `gorm:"primaryKey"`
	RefreshToken          string `gorm:"uniqueIndex"`
	ClientID              string `gorm:"not null;index"`
	UserID                string `gorm:"not null"`
	GrantID               string `gorm:"not null"`
	Scope                 string
	ExpiresAt             time.Time `gorm:"not null;index"`
	RefreshTokenExpiresAt time.Time `gorm:"not null"`
	CreatedAt             time.Time `gorm:"autoCreateTime"`
	Revoked               bool      `gorm:"default:false;index"`
	RevokedAt             *time.Time
}

// Grant represents an authorization grant
type Grant struct {
	ID                  string      `gorm:"primaryKey" json:"id"`
	ClientID            string      `gorm:"not null;index" json:"client_id"`
	UserID              string      `gorm:"not null;index" json:"user_id"`
	Scope               StringSlice `gorm:"type:text" json:"scope"`
	Metadata            JSON        `gorm:"type:text" json:"metadata"`
	Props               JSON        `gorm:"type:text" json:"props"`
	CreatedAt           int64       `gorm:"not null" json:"created_at"`
	ExpiresAt           int64       `gorm:"not null" json:"expires_at"`
	CodeChallenge       string      `json:"code_challenge,omitempty"`
	CodeChallengeMethod string      `json:"code_challenge_method,omitempty"`
}

// AuthorizationCode represents an authorization code
type AuthorizationCode struct {
	Code      string    `gorm:"primaryKey"`
	GrantID   string    `gorm:"not null"`
	UserID    string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// StoredAuthRequest represents a stored OAuth authorization request for state management
type StoredAuthRequest struct {
	Key       string    `gorm:"primaryKey"`
	Data      JSON      `gorm:"type:jsonb;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}
