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

	// handleRefresh performs a refresh token request with the given form values against a grant that was originally
	// granted the "https://api.ory.sh/" audience.
	handleRefresh := func(t *testing.T, form url.Values) (fosite.AccessRequester, error) {
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

		return request, handler.HandleTokenEndpointRequest(ctx, request)
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
}
