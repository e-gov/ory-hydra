// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fositex_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/ory/hydra/v2/fositex"
)

func TestRefreshTokenGrantHandler(t *testing.T) {
	ctx := context.Background()
	config := &authHandoverConfig{Config: &fosite.Config{GlobalSecret: []byte("thirty-two-bytes-of-super-secret")}}
	strategy := compose.NewOAuth2HMACStrategy(config.Config)
	client := &fosite.DefaultClient{
		ID:         "client",
		GrantTypes: fosite.Arguments{"refresh_token"},
		Scopes:     fosite.Arguments{"openid", "offline"},
		Audience:   fosite.Arguments{"https://api.ory.sh/", "https://other.ory.sh/"},
	}

	// refresh performs a refresh token request with the given form values against a grant that was originally granted
	// the "https://api.ory.sh/" audience. When populate is true, the token endpoint response is populated as well,
	// which rotates the refresh token and stores the sessions of the issued tokens.
	refresh := func(t *testing.T, form url.Values, populate bool) (fosite.AccessRequester, *storage.MemoryStore, error) {
		store := storage.NewMemoryStore()
		handler := fositex.RefreshTokenGrantFactory(config, store, strategy).(*fositex.RefreshTokenGrantHandler)

		originalRequest := &fosite.Request{
			ID:                "original-request",
			RequestedAt:       time.Now().UTC(),
			Client:            client,
			RequestedScope:    fosite.Arguments{"openid", "offline"},
			GrantedScope:      fosite.Arguments{"openid", "offline"},
			RequestedAudience: fosite.Arguments{"https://api.ory.sh/"},
			GrantedAudience:   fosite.Arguments{"https://api.ory.sh/"},
			Session:           &fosite.DefaultSession{},
			Form:              url.Values{},
		}

		refreshToken, signature, err := strategy.GenerateRefreshToken(ctx, originalRequest)
		require.NoError(t, err)
		require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, originalRequest))

		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)

		request := fosite.NewAccessRequest(&fosite.DefaultSession{})
		request.Client = client
		request.GrantTypes = fosite.Arguments{"refresh_token"}
		request.Form = form
		// This is what fosite.Fosite.NewAccessRequest does before it calls the token endpoint handlers.
		request.SetRequestedAudience(fosite.GetAudiences(form))

		if err := handler.HandleTokenEndpointRequest(ctx, request); err != nil {
			return request, store, err
		}
		if !populate {
			return request, store, nil
		}

		return request, store, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
	}

	// handleRefresh performs a refresh token request without populating the token endpoint response.
	handleRefresh := func(t *testing.T, form url.Values) (fosite.AccessRequester, error) {
		request, _, err := refresh(t, form, false)
		return request, err
	}

	// storedRefreshTokenSession returns the session of the refresh token that rotation has just created. Rotation
	// leaves the original refresh token behind as an inactive session, which the store does not return.
	storedRefreshTokenSession := func(t *testing.T, store *storage.MemoryStore) fosite.Requester {
		var sessions []fosite.Requester
		for signature := range store.RefreshTokens {
			session, err := store.GetRefreshTokenSession(ctx, signature, nil)
			if err == nil {
				sessions = append(sessions, session)
			}
		}
		require.Len(t, sessions, 1)
		return sessions[0]
	}

	t.Run("case=keeps the original audience when no audience is requested", func(t *testing.T) {
		request, err := handleRefresh(t, url.Values{})
		require.NoError(t, err)

		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, request.GetRequestedAudience())
		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, request.GetGrantedAudience())
		assert.EqualValues(t, fosite.Arguments{"openid", "offline"}, request.GetGrantedScopes())
	})

	t.Run("case=replaces the original audience with the requested audience", func(t *testing.T) {
		request, err := handleRefresh(t, url.Values{"audience": {"https://other.ory.sh/"}})
		require.NoError(t, err)

		assert.EqualValues(t, fosite.Arguments{"https://other.ory.sh/"}, request.GetRequestedAudience())
		assert.EqualValues(t, fosite.Arguments{"https://other.ory.sh/"}, request.GetGrantedAudience())
		assert.EqualValues(t, fosite.Arguments{"openid", "offline"}, request.GetGrantedScopes())
	})

	t.Run("case=clears the audience when the audience parameter is empty", func(t *testing.T) {
		request, err := handleRefresh(t, url.Values{"audience": {""}})
		require.NoError(t, err)

		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=fails when the requested audience has not been whitelisted", func(t *testing.T) {
		request, err := handleRefresh(t, url.Values{"audience": {"https://not-ory-api/"}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=does not store the requested audience on the rotated refresh token", func(t *testing.T) {
		request, store, err := refresh(t, url.Values{"audience": {"https://other.ory.sh/"}}, true)
		require.NoError(t, err)

		// The tokens issued for this request are addressed to the requested audience ...
		assert.EqualValues(t, fosite.Arguments{"https://other.ory.sh/"}, request.GetGrantedAudience())

		// ... but the next refresh must restore the audience of the original request, not the requested one.
		stored := storedRefreshTokenSession(t, store)
		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, stored.GetGrantedAudience())
		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, stored.GetRequestedAudience())
		assert.EqualValues(t, fosite.Arguments{"openid", "offline"}, stored.GetGrantedScopes())
	})

	t.Run("case=stores the original audience on the rotated refresh token when no audience is requested", func(t *testing.T) {
		_, store, err := refresh(t, url.Values{}, true)
		require.NoError(t, err)

		stored := storedRefreshTokenSession(t, store)
		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, stored.GetGrantedAudience())
		assert.EqualValues(t, fosite.Arguments{"https://api.ory.sh/"}, stored.GetRequestedAudience())
	})
}

// authHandoverConfig provides the auth handover audience, like fositex.Config does.
type authHandoverConfig struct {
	*fosite.Config
	authHandoverAudience string
}

func (c *authHandoverConfig) GetAuthHandoverAudience(context.Context) string {
	return c.authHandoverAudience
}

func TestRefreshTokenGrantHandlerAuthHandover(t *testing.T) {
	ctx := context.Background()
	const authHandoverAudience = "https://govsso.ory.sh/"
	newConfig := func(authHandoverAudience string) *authHandoverConfig {
		return &authHandoverConfig{
			Config:               &fosite.Config{GlobalSecret: []byte("thirty-two-bytes-of-super-secret")},
			authHandoverAudience: authHandoverAudience,
		}
	}
	// The auth handover audience is deliberately not whitelisted in the client's audience.
	newClient := func(scopes ...string) *fosite.DefaultClient {
		return &fosite.DefaultClient{
			ID:         "client",
			GrantTypes: fosite.Arguments{"refresh_token"},
			Scopes:     scopes,
			Audience:   fosite.Arguments{"https://api.ory.sh/"},
		}
	}
	authHandoverClient := newClient("openid", "offline", "auth_handover")

	// refresh handles a refresh token request with the given form values against a grant that was originally granted
	// the "https://api.ory.sh/" audience.
	refresh := func(t *testing.T, config *authHandoverConfig, client fosite.Client, form url.Values) (fosite.AccessRequester, error) {
		strategy := compose.NewOAuth2HMACStrategy(config.Config)
		store := storage.NewMemoryStore()
		handler := fositex.RefreshTokenGrantFactory(config, store, strategy).(*fositex.RefreshTokenGrantHandler)

		originalRequest := &fosite.Request{
			ID:                "original-request",
			RequestedAt:       time.Now().UTC(),
			Client:            client,
			RequestedScope:    fosite.Arguments{"openid", "offline"},
			GrantedScope:      fosite.Arguments{"openid", "offline"},
			RequestedAudience: fosite.Arguments{"https://api.ory.sh/"},
			GrantedAudience:   fosite.Arguments{"https://api.ory.sh/"},
			Session:           &fosite.DefaultSession{},
			Form:              url.Values{},
		}

		refreshToken, signature, err := strategy.GenerateRefreshToken(ctx, originalRequest)
		require.NoError(t, err)
		require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, originalRequest))

		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)

		request := fosite.NewAccessRequest(&fosite.DefaultSession{})
		request.Client = client
		request.GrantTypes = fosite.Arguments{"refresh_token"}
		request.Form = form
		// This is what fosite.Fosite.NewAccessRequest does before it calls the token endpoint handlers.
		request.SetRequestedScopes(fosite.RemoveEmpty(strings.Split(form.Get("scope"), " ")))
		request.SetRequestedAudience(fosite.GetAudiences(form))

		return request, handler.HandleTokenEndpointRequest(ctx, request)
	}

	t.Run("case=grants the auth handover audience although the client has not whitelisted it", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), authHandoverClient,
			url.Values{"scope": {"auth_handover"}, "audience": {authHandoverAudience}})
		require.NoError(t, err)

		assert.EqualValues(t, fosite.Arguments{authHandoverAudience}, request.GetRequestedAudience())
		assert.EqualValues(t, fosite.Arguments{authHandoverAudience}, request.GetGrantedAudience())
	})

	t.Run("case=fails when the auth handover audience is combined with another audience", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), authHandoverClient,
			url.Values{"scope": {"auth_handover"}, "audience": {"https://api.ory.sh/ " + authHandoverAudience}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=fails when a path below the auth handover audience is requested", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), authHandoverClient,
			url.Values{"scope": {"auth_handover"}, "audience": {authHandoverAudience + "some/path"}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=fails when the auth handover audience is requested in a different case", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), authHandoverClient,
			url.Values{"scope": {"auth_handover"}, "audience": {strings.ToUpper(authHandoverAudience)}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=fails when the client is not allowed the auth handover scope", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), newClient("openid", "offline"),
			url.Values{"scope": {"auth_handover"}, "audience": {authHandoverAudience}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=factory panics when the config does not provide the auth handover audience", func(t *testing.T) {
		config := &fosite.Config{GlobalSecret: []byte("thirty-two-bytes-of-super-secret")}
		assert.Panics(t, func() {
			fositex.RefreshTokenGrantFactory(config, storage.NewMemoryStore(), compose.NewOAuth2HMACStrategy(config))
		})
	})

	t.Run("case=fails when the auth handover audience is not configured", func(t *testing.T) {
		request, err := refresh(t, newConfig(""), authHandoverClient,
			url.Values{"scope": {"auth_handover"}, "audience": {authHandoverAudience}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})

	t.Run("case=fails when the auth handover audience is requested without the auth handover scope", func(t *testing.T) {
		request, err := refresh(t, newConfig(authHandoverAudience), authHandoverClient,
			url.Values{"audience": {authHandoverAudience}})
		require.Error(t, err)

		assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
		assert.Empty(t, request.GetGrantedAudience())
	})
}
