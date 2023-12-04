package jwk

import (
	"context"
	"github.com/gofrs/uuid"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
	"gopkg.in/square/go-jose.v2"
	"net"
)

var fetchKey = "fetch"

type CachedKeys interface {
	Get(ctx context.Context) (private *jose.JSONWebKey, err error)
}

type DefaultCachedKeys struct {
	r          InternalRegistry
	setID      string
	fetchGroup singleflight.Group
	private    *jose.JSONWebKey
}

type resultWrapper struct {
	private *jose.JSONWebKey
}

func NewDefaultCachedKeys(r InternalRegistry, setID string) *DefaultCachedKeys {
	return &DefaultCachedKeys{
		r:     r,
		setID: setID,
	}
}

func (c *DefaultCachedKeys) Get(ctx context.Context) (private *jose.JSONWebKey, err error) {
	result, err, _ := c.fetchGroup.Do(fetchKey, func() (interface{}, error) {
		if c.private != nil {
			return resultWrapper{c.private}, nil
		}
		private, err := c.fetch(ctx)
		if err != nil {
			return nil, err
		}
		c.private = private
		return resultWrapper{private}, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(resultWrapper).private, nil
}

func (c *DefaultCachedKeys) fetch(ctx context.Context) (private *jose.JSONWebKey, err error) {
	private, err = GetOrGenerateKeys(ctx, c.r, c.r.KeyManager(), c.setID, uuid.Must(uuid.NewV4()).String(), string(jose.RS256))
	if err == nil {
		return private, nil
	}

	var netError net.Error
	if errors.As(err, &netError) {
		return nil, errors.WithStack(fosite.ErrServerError.
			WithHintf(`Could not ensure that signing keys for "%s" exists. A network error occurred, see error for specific details.`, c.setID))
	}

	return nil, errors.WithStack(fosite.ErrServerError.
		WithWrap(err).
		WithHintf(`Could not ensure that signing keys for "%s" exists. If you are running against a persistent SQL database this is most likely because your "secrets.system" ("SECRETS_SYSTEM" environment variable) is not set or changed. When running with an SQL database backend you need to make sure that the secret is set and stays the same, unless when doing key rotation. This may also happen when you forget to run "hydra migrate sql..`, c.setID))

}
