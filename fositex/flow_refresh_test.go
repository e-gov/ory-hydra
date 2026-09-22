// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fositex_test

import (
	"context"
	"net/url"
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
	config := &fosite.Config{GlobalSecret: []byte("thirty-two-bytes-of-super-secret")}
	strategy := compose.NewOAuth2HMACStrategy(config)
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
