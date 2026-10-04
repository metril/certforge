package vault

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Auth selects how a Client logs in to Vault.
type Auth interface {
	isVaultAuth()
}

// TokenAuth authenticates with a pre-issued Vault token. Login is then a
// no-op that just adopts Token; there is no login call for token auth.
type TokenAuth struct {
	Token string
}

func (TokenAuth) isVaultAuth() {}

// AppRoleAuth authenticates via Vault's AppRole auth method. Mount defaults
// to "approle" when empty.
type AppRoleAuth struct {
	RoleID   string
	SecretID string
	Mount    string
}

func (AppRoleAuth) isVaultAuth() {}

func (a AppRoleAuth) mount() string {
	if a.Mount == "" {
		return "approle"
	}
	return a.Mount
}

// loginResponse decodes both the AppRole login and the renew-self
// responses, which share the same "auth" envelope shape.
type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// Login authenticates c according to its Auth: TokenAuth just adopts its
// token, AppRoleAuth calls Vault's AppRole login endpoint.
func (c *Client) Login(ctx context.Context) error {
	switch a := c.auth.(type) {
	case TokenAuth:
		c.setToken(a.Token)
		return nil
	case AppRoleAuth:
		var resp loginResponse
		body := map[string]string{"role_id": a.RoleID, "secret_id": a.SecretID}
		path := "/v1/auth/" + escapePath(a.mount()) + "/login"
		if err := c.doJSON(ctx, http.MethodPost, path, body, &resp, requestOpts{noRelogin: true}); err != nil {
			return c.Redact(err)
		}
		c.setToken(resp.Auth.ClientToken)
		c.mu.Lock()
		c.leaseSeconds = resp.Auth.LeaseDuration
		c.renewable = resp.Auth.Renewable
		c.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("vault: unsupported auth type %T", c.auth)
	}
}

// RenewSelf extends the current token's TTL.
func (c *Client) RenewSelf(ctx context.Context) error {
	var resp loginResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/token/renew-self", map[string]any{}, &resp, requestOpts{})
	if err != nil {
		return c.Redact(err)
	}
	c.mu.Lock()
	c.leaseSeconds = resp.Auth.LeaseDuration
	c.renewable = resp.Auth.Renewable
	c.mu.Unlock()
	return nil
}

// TokenInfo is the current token's state, from LookupSelf.
type TokenInfo struct {
	TTL       time.Duration
	Policies  []string
	Renewable bool
}

// LookupSelf reports the current token's TTL, policies and renewability.
func (c *Client) LookupSelf(ctx context.Context) (TokenInfo, error) {
	var resp struct {
		Data struct {
			TTL       int      `json:"ttl"`
			Policies  []string `json:"policies"`
			Renewable bool     `json:"renewable"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, &resp, requestOpts{}); err != nil {
		return TokenInfo{}, c.Redact(err)
	}
	return TokenInfo{
		TTL:       time.Duration(resp.Data.TTL) * time.Second,
		Policies:  resp.Data.Policies,
		Renewable: resp.Data.Renewable,
	}, nil
}

// HealthInfo is Vault's /sys/health body.
type HealthInfo struct {
	Initialized bool
	Sealed      bool
	Standby     bool
	Version     string
}

// Health reports Vault's reachability and state. 200, 429 (standby), 472
// (DR secondary) and 473 (performance standby) are reachable and return no
// error; 501 (not initialized) and 503 (sealed) are failed states and
// return an *APIError, without being retried (they are meaningful, stable
// answers, not transient failures).
func (c *Client) Health(ctx context.Context) (HealthInfo, error) {
	var resp HealthInfo
	opts := requestOpts{
		accept:    []int{http.StatusTooManyRequests, 472, 473},
		noRetry:   []int{http.StatusNotImplemented, http.StatusServiceUnavailable},
		noRelogin: true,
	}
	path := "/v1/sys/health?standbyok=true&perfstandbyok=true"
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp, opts); err != nil {
		return HealthInfo{}, c.Redact(err)
	}
	return resp, nil
}
