// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fositex

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/x/errorsx"
)

var _ fosite.TokenEndpointHandler = (*RefreshTokenGrantHandler)(nil)

// RefreshTokenGrantHandler decorates fosite's refresh token grant handler, which restores the requested and granted
// audience from the original request and would therefore ignore an `audience` parameter sent with the refresh request.
// If the refresh request contains an `audience` parameter, the requested audience replaces the audience granted during
// the original request.
//
// That replacement applies to the tokens issued for this request only. The decorated handler rotates the refresh token
// and stores the current request as the new refresh token's original request, so a persisted replacement would be
// restored by every later refresh.
//
// A refresh request for an auth handover token (one with the `auth_handover` scope) is rejected unless the client is
// allowed the scope. The decorated handler only checks the scopes granted to the original request against the client,
// not the ones requested with the `scope` parameter of this request.
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
	// The scope marks the request rather than authorizing access, so it must be whitelisted in the client's scopes
	// exactly; a wildcard scope strategy would otherwise let a broad client scope such as `*` match it.
	if c.CanHandleTokenEndpointRequest(ctx, request) && oauth2.RequestsAuthHandover(request) &&
		!request.GetClient().GetScopes().Has(oauth2.AuthHandoverScope) {
		return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", oauth2.AuthHandoverScope))
	}

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

func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {
	// The decorated handler rejects grants it cannot handle; check first, so that the lookup below is only made for
	// the refresh requests that actually need it.
	if !c.CanHandleTokenEndpointRequest(ctx, request) || !request.GetRequestForm().Has("audience") {
		return c.RefreshTokenGrantHandler.PopulateTokenEndpointResponse(ctx, request, responder)
	}

	// The audience granted from the `audience` parameter must not reach the request that the decorated handler stores
	// as the rotated refresh token's original request, or the next refresh would restore it. Recover the audience of
	// the original request, so that it can be put back on the stored request.
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, request.GetRequestForm().Get("refresh_token"))
	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
	if err != nil {
		// The decorated handler looks the same session up and reports the failure as it normally would, including
		// refresh token reuse detection. Leave that to it rather than duplicating it here.
		return c.RefreshTokenGrantHandler.PopulateTokenEndpointResponse(ctx, request, responder)
	}

	return c.RefreshTokenGrantHandler.PopulateTokenEndpointResponse(ctx, &audienceRestoringRequester{
		AccessRequester:   request,
		requestedAudience: originalRequest.GetRequestedAudience(),
		grantedAudience:   originalRequest.GetGrantedAudience(),
	}, responder)
}

// audienceDiscardingRequester discards audience grants; see RefreshTokenGrantHandler.HandleTokenEndpointRequest.
type audienceDiscardingRequester struct {
	fosite.AccessRequester
}

func (*audienceDiscardingRequester) GrantAudience(string) {}

// audienceRestoringRequester restores the audience of the original request on the sanitized request that is stored,
// leaving the audience of the request itself - and therefore of the tokens generated from it - untouched; see
// RefreshTokenGrantHandler.PopulateTokenEndpointResponse.
type audienceRestoringRequester struct {
	fosite.AccessRequester
	requestedAudience fosite.Arguments
	grantedAudience   fosite.Arguments
}

func (r *audienceRestoringRequester) Sanitize(allowedParameters []string) fosite.Requester {
	sanitized := r.AccessRequester.Sanitize(allowedParameters)
	if request, ok := sanitized.(*fosite.Request); ok {
		request.RequestedAudience = r.requestedAudience
		request.GrantedAudience = r.grantedAudience
	}
	return sanitized
}
