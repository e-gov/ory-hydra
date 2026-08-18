// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fositex

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	foauth2 "github.com/ory/fosite/handler/oauth2"
)

var _ fosite.TokenEndpointHandler = (*RefreshTokenGrantHandler)(nil)

// RefreshTokenGrantHandler decorates fosite's refresh token grant handler, which restores the requested and granted
// audience from the original request and would therefore ignore an `audience` parameter sent with the refresh request.
// If the refresh request contains an `audience` parameter, the requested audience replaces the audience granted during
// the original request.
type RefreshTokenGrantHandler struct {
	*foauth2.RefreshTokenGrantHandler
}

// RefreshTokenGrantFactory creates a RefreshTokenGrantHandler.
func RefreshTokenGrantFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &RefreshTokenGrantHandler{
		RefreshTokenGrantHandler: compose.OAuth2RefreshTokenGrantFactory(config, storage, strategy).(*foauth2.RefreshTokenGrantHandler),
	}
}

func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !request.GetRequestForm().Has("audience") {
		return c.RefreshTokenGrantHandler.HandleTokenEndpointRequest(ctx, request)
	}

	// The `audience` parameter has already been parsed into the requested audience when the access request was
	// created, but the decorated handler overwrites it with the audience of the original request.
	requestedAudience := request.GetRequestedAudience()

	// The decorated handler also grants the audience of the original request. Hide those grants from it, so that the
	// requested audience replaces them instead of being added to them.
	if err := c.RefreshTokenGrantHandler.HandleTokenEndpointRequest(ctx, &audienceDiscardingRequester{AccessRequester: request}); err != nil {
		return err
	}

	if err := c.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), requestedAudience); err != nil {
		return err
	}

	request.SetRequestedAudience(requestedAudience)
	for _, audience := range requestedAudience {
		request.GrantAudience(audience)
	}

	return nil
}

// audienceDiscardingRequester discards audience grants; see RefreshTokenGrantHandler.HandleTokenEndpointRequest.
type audienceDiscardingRequester struct {
	fosite.AccessRequester
}

func (*audienceDiscardingRequester) GrantAudience(string) {}
