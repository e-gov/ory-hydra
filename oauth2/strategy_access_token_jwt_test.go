// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/hydra/v2/jwk"
)

type testJWTStrategyConfig struct{}

func (testJWTStrategyConfig) GetAccessTokenIssuer(context.Context) string {
	return "https://hydra.localhost"
}

func (testJWTStrategyConfig) GetJWTScopeField(context.Context) jwt.JWTScopeFieldEnum {
	return jwt.JWTScopeFieldString
}

func newTestJWTStrategy(t *testing.T) *DefaultJWTStrategy {
	t.Helper()

	keys, err := jwk.GenerateJWK(context.Background(), jose.ES256, "test-kid", "sig")
	require.NoError(t, err)

	return &DefaultJWTStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: func(context.Context) (interface{}, error) {
			return &keys.Keys[0], nil
		}},
		Config: testJWTStrategyConfig{},
	}
}

// accessTokenClaims decodes the token payload without verifying the signature.
func accessTokenClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

type testCase struct {
	name string
	// sessionScope is the scope the token hook put on the session.
	sessionScope []string
	// scopeParameter is the raw `scope` request parameter, as sent to the token endpoint.
	scopeParameter string
	// requestedScopes is what fosite exposes through GetRequestedScopes. The refresh token grant
	// handler overwrites this with the scopes of the original authorize request, dropping anything
	// that only ever appeared in scopeParameter.
	requestedScopes []string
	grantedScopes   []string
	expectedScope   interface{}
}

// The `scope` claim is reserved for auth handover tokens - every other access token must be issued
// without one, even when the token hook returned a scope for the session. The handover scope is only
// ever requested, never granted, so the granted scopes must not influence the claim.
func TestGenerateAccessTokenScopeClaim(t *testing.T) {
	ctx := context.Background()
	strategy := newTestJWTStrategy(t)

	newRequest := func(tc testCase) *fosite.AccessRequest {
		session := NewSession("foo")
		session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(time.Hour))
		session.Scope = tc.sessionScope

		request := fosite.NewAccessRequest(session)
		request.SetRequestedScopes(tc.requestedScopes)
		for _, scope := range tc.grantedScopes {
			request.GrantScope(scope)
		}
		if tc.scopeParameter != "" {
			request.Form = url.Values{"scope": {tc.scopeParameter}}
		}
		return request
	}

	for _, tc := range []testCase{
		{
			// The auth handover scope is never granted, so the claim must be driven by the
			// requested scopes alone.
			name:            "auth handover requested but not granted",
			sessionScope:    []string{"read", "write"},
			requestedScopes: []string{AuthHandoverScope},
			expectedScope:   "read write",
		},
		{
			// A refresh request carrying `scope=auth_handover`: fosite has replaced the requested
			// scopes with those of the original authorize request, so only the raw parameter is left
			// to go on.
			name:            "auth handover in the scope parameter only",
			sessionScope:    []string{"read", "write"},
			scopeParameter:  AuthHandoverScope,
			requestedScopes: []string{"openid", "offline_access"},
			grantedScopes:   []string{"openid", "offline_access"},
			expectedScope:   "read write",
		},
		{
			name:            "auth handover in the scope parameter alongside other scopes",
			sessionScope:    []string{"read"},
			scopeParameter:  "openid " + AuthHandoverScope,
			requestedScopes: []string{"openid", "offline_access"},
			grantedScopes:   []string{"openid", "offline_access"},
			expectedScope:   "read",
		},
		{
			// The parameter is authoritative where present - a narrowing refresh request that drops
			// the handover scope must drop the claim with it.
			name:            "scope parameter without auth handover",
			sessionScope:    []string{"read", "write"},
			scopeParameter:  "openid",
			requestedScopes: []string{AuthHandoverScope},
			expectedScope:   nil,
		},
		{
			name:            "auth handover requested alongside other scopes",
			sessionScope:    []string{"read"},
			requestedScopes: []string{"openid", AuthHandoverScope},
			grantedScopes:   []string{"openid"},
			expectedScope:   "read",
		},
		{
			name:            "auth handover not requested",
			sessionScope:    []string{"read", "write"},
			requestedScopes: []string{"openid", "offline_access"},
			grantedScopes:   []string{"openid", "offline_access"},
			expectedScope:   nil,
		},
		{
			name:          "no scope requested at all",
			sessionScope:  []string{"read"},
			expectedScope: nil,
		},
		{
			name:            "auth handover requested but session carries no scope",
			requestedScopes: []string{AuthHandoverScope},
			expectedScope:   nil,
		},
		{
			name:            "auth handover requested but session scope is empty",
			sessionScope:    []string{},
			requestedScopes: []string{AuthHandoverScope},
			expectedScope:   nil,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			token, _, err := strategy.GenerateAccessToken(ctx, newRequest(tc))
			require.NoError(t, err)

			claims := accessTokenClaims(t, token)
			if tc.expectedScope == nil {
				assert.NotContains(t, claims, "scope")
				assert.NotContains(t, claims, "scp")
				return
			}
			assert.Equal(t, tc.expectedScope, claims["scope"])
		})
	}
}
