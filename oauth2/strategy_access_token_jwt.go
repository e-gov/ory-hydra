package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
)

// AuthHandoverScope is the only scope for which access tokens carry a `scope` claim. Access tokens
// issued for any other request must not include a scope, so the claim is omitted entirely unless this
// scope was requested.
//
// The scope is deliberately never granted - it marks the request rather than authorizing access - so
// it must not be looked up in the granted scopes.
const AuthHandoverScope = "auth_handover"

// DefaultJWTStrategy is a JWT RS256 strategy.
type DefaultJWTStrategy struct {
	jwt.Signer
	HMACSHAStrategy *foauth2.HMACSHAStrategy
	Config          interface {
		fosite.AccessTokenIssuerProvider
		fosite.JWTScopeFieldProvider
	}
}

func (h DefaultJWTStrategy) signature(token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}

	return split[2]
}

func (h DefaultJWTStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.signature(token)
}

func (h *DefaultJWTStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(ctx, fosite.AccessToken, requester)
}

func (h *DefaultJWTStrategy) ValidateAccessToken(ctx context.Context, _ fosite.Requester, token string) error {
	_, err := validate(ctx, h.Signer, token)
	return err
}

func (h DefaultJWTStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.HMACSHAStrategy.RefreshTokenSignature(ctx, token)
}

func (h DefaultJWTStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.HMACSHAStrategy.AuthorizeCodeSignature(ctx, token)
}

func (h *DefaultJWTStrategy) GenerateRefreshToken(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateRefreshToken(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateRefreshToken(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateRefreshToken(ctx, req, token)
}

func (h *DefaultJWTStrategy) GenerateAuthorizeCode(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateAuthorizeCode(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateAuthorizeCode(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateAuthorizeCode(ctx, req, token)
}

func validate(ctx context.Context, jwtStrategy jwt.Signer, token string) (t *jwt.Token, err error) {
	t, err = jwtStrategy.Decode(ctx, token)
	if err == nil {
		err = t.Claims.Valid()
		return
	}

	var e *jwt.ValidationError
	if err != nil && errors.As(err, &e) {
		err = errorsx.WithStack(toRFCErr(e).WithWrap(err).WithDebug(err.Error()))
	}

	return
}

func toRFCErr(v *jwt.ValidationError) *fosite.RFC6749Error {
	switch {
	case v == nil:
		return nil
	case v.Has(jwt.ValidationErrorMalformed):
		return fosite.ErrInvalidTokenFormat
	case v.Has(jwt.ValidationErrorUnverifiable | jwt.ValidationErrorSignatureInvalid):
		return fosite.ErrTokenSignatureMismatch
	case v.Has(jwt.ValidationErrorExpired):
		return fosite.ErrTokenExpired
	case v.Has(jwt.ValidationErrorAudience |
		jwt.ValidationErrorIssuedAt |
		jwt.ValidationErrorIssuer |
		jwt.ValidationErrorNotValidYet |
		jwt.ValidationErrorId |
		jwt.ValidationErrorClaimsInvalid):
		return fosite.ErrTokenClaim
	default:
		return fosite.ErrRequestUnauthorized
	}
}

// requestsAuthHandover reports whether the request asks for an auth handover token.
//
// The `scope` request parameter is authoritative wherever it is present. The refresh token grant
// handler overwrites the requested scopes with those of the original authorize request, so a `scope`
// parameter sent with a refresh request never reaches GetRequestedScopes() - the same reason the
// `audience` parameter needs restoring in the token handler. Reading the form here also keeps this
// check aligned with what the token hook sees in `request.payload`, which is what populates the
// session scope in the first place.
//
// Where the parameter is absent - the `authorization_code` grant sends no scope to the token endpoint
// - fosite has restored the scopes requested during the authorize request, so those are used instead.
//
// Either way this is a sufficient authorization check on its own: a client that is not allowed the
// scope cannot request it, fosite rejects the request before a token is ever generated.
func requestsAuthHandover(requester fosite.Requester) bool {
	if raw := requester.GetRequestForm().Get("scope"); raw != "" {
		return fosite.Arguments(strings.Fields(raw)).Has(AuthHandoverScope)
	}

	return requester.GetRequestedScopes().Has(AuthHandoverScope)
}

func (h *DefaultJWTStrategy) generate(ctx context.Context, tokenType fosite.TokenType, requester fosite.Requester) (string, string, error) {

	if jwtSession, ok := requester.GetSession().(foauth2.JWTSessionContainer); !ok {
		return "", "", errors.Errorf("Session must be of type JWTSessionContainer but got type: %T", requester.GetSession())
	} else if jwtSession.GetJWTClaims() == nil {
		return "", "", errors.New("GetTokenClaims() must not be nil")
	} else {
		// The scope claim is only emitted for auth handover tokens. It must stay nil for every other
		// request, because fosite omits the claim for a nil scope but renders an empty one ("scope": "")
		// for a non-nil empty slice.
		var scope fosite.Arguments
		if s, ok := requester.GetSession().(*Session); ok && len(s.Scope) > 0 &&
			requestsAuthHandover(requester) {
			scope = s.Scope
		}
		claims := jwtSession.GetJWTClaims().
			With(
				jwtSession.GetExpiresAt(tokenType),
				scope,
				requester.GetGrantedAudience(),
			).
			WithDefaults(
				time.Now().UTC(),
				h.Config.GetAccessTokenIssuer(ctx),
			).
			WithScopeField(
				h.Config.GetJWTScopeField(ctx),
			)

		return h.Signer.Generate(ctx, claims.ToMapClaims(), jwtSession.GetJWTHeader())
	}
}
