// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"context"
	"github.com/ory/x/josex"

	"gopkg.in/square/go-jose.v2"

	"github.com/ory/hydra/v2/driver/config"

	"github.com/pkg/errors"

	"github.com/ory/fosite/token/jwt"
)

type JWTSigner interface {
	GetPublicKeyID(ctx context.Context) (string, error)
	GetPublicKey(ctx context.Context) (jose.JSONWebKey, error)
	jwt.Signer
}

type DefaultJWTSigner struct {
	*jwt.DefaultSigner
	r     InternalRegistry
	c     *config.DefaultProvider
	setID string
	k     CachedKeys
}

func NewDefaultJWTSigner(c *config.DefaultProvider, r InternalRegistry, setID string) *DefaultJWTSigner {
	j := &DefaultJWTSigner{
		c:             c,
		r:             r,
		setID:         setID,
		DefaultSigner: &jwt.DefaultSigner{},
		k:             NewDefaultCachedKeys(r, setID),
	}
	j.DefaultSigner.GetPrivateKey = j.getPrivateKey
	return j
}

func (j *DefaultJWTSigner) getKeys(ctx context.Context) (private *jose.JSONWebKey, err error) {
	return j.k.Get(ctx)
}

func (j *DefaultJWTSigner) GetPublicKeyID(ctx context.Context) (string, error) {
	private, err := j.getKeys(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return josex.ToPublicKey(private).KeyID, nil
}

func (j *DefaultJWTSigner) GetPublicKey(ctx context.Context) (jose.JSONWebKey, error) {
	private, err := j.getKeys(ctx)
	if err != nil {
		return jose.JSONWebKey{}, errors.WithStack(err)
	}
	return josex.ToPublicKey(private), nil
}

func (j *DefaultJWTSigner) getPrivateKey(ctx context.Context) (interface{}, error) {
	private, err := j.getKeys(ctx)
	if err != nil {
		return nil, err
	}

	return private, nil
}
