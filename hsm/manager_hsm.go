// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build hsm
// +build hsm

package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"

	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/x/otelx"
	"github.com/ory/x/stringslice"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/jwk"

	"github.com/ory/hydra/v2/x"

	"github.com/ThalesIgnite/crypto11"
	"go.opentelemetry.io/otel"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
)

const tracingComponent = "github.com/ory/hydra/hsm"

type KeyManager struct {
	jwk.Manager
	Context
	c             config.DefaultProvider
	keySetCacheMu sync.RWMutex
	keySetCache   map[string]jose.JSONWebKeySet
}

var ErrPreGeneratedKeys = &fosite.RFC6749Error{
	CodeField:        http.StatusBadRequest,
	ErrorField:       http.StatusText(http.StatusBadRequest),
	DescriptionField: "Generating/adding/updating/deleting keys on the Hardware Security Module is not implemented.",
}

func NewKeyManager(hsm Context, config *config.DefaultProvider) *KeyManager {
	return &KeyManager{
		Context:     hsm,
		c:           *config,
		keySetCache: make(map[string]jose.JSONWebKeySet),
	}
}

func (m *KeyManager) GenerateAndPersistKeySet(_ context.Context, _, _, _, _ string) (*jose.JSONWebKeySet, error) {
	return nil, errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) GetKey(ctx context.Context, set, kid string) (*jose.JSONWebKeySet, error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "hsm.GetKey")
	defer span.End()
	attrs := map[string]string{
		"set": set,
		"kid": kid,
	}
	span.SetAttributes(otelx.StringAttrs(attrs)...)

	set = m.prefixKeySet(set)

	keyPair, err := m.FindKeyPair([]byte(kid), []byte(set))
	if err != nil {
		return nil, err
	}

	if keyPair == nil {
		return nil, errors.WithStack(x.ErrNotFound)
	}

	_, alg, use, err := m.getKeySetAttributes(ctx, keyPair, []byte(kid))
	if err != nil {
		return nil, err
	}

	return createKeySet(keyPair, kid, alg, use), nil
}

func (m *KeyManager) GetKeySet(ctx context.Context, set string) (*jose.JSONWebKeySet, error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "hsm.GetKeySet")
	defer span.End()
	attrs := map[string]string{
		"set": set,
	}
	span.SetAttributes(otelx.StringAttrs(attrs)...)

	set = m.prefixKeySet(set)

	keyPairs, err := m.FindKeyPairs(nil, []byte(set))
	if err != nil {
		return nil, err
	}

	if keyPairs == nil {
		return nil, errors.WithStack(x.ErrNotFound)
	}

	var keys []jose.JSONWebKey
	for _, keyPair := range keyPairs {
		kid, alg, use, err := m.getKeySetAttributes(ctx, keyPair, nil)
		if err != nil {
			return nil, err
		}
		keys = append(keys, createKeys(keyPair, kid, alg, use)...)
	}

	return &jose.JSONWebKeySet{
		Keys: keys,
	}, nil
}

func (m *KeyManager) GetWellKnownKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet
	for _, set := range stringslice.Unique(m.c.WellKnownKeys(ctx)) {
		m.keySetCacheMu.RLock()
		cachedSet, ok := m.keySetCache[set]
		m.keySetCacheMu.RUnlock()
		if ok {
			jwks.Keys = append(jwks.Keys, cachedSet.Keys...)
		} else if keys, err := m.GetKeySet(ctx, set); err == nil {
			keys = jwk.ExcludePrivateKeys(keys)
			jwks.Keys = append(jwks.Keys, keys.Keys...)
			m.keySetCacheMu.Lock()
			m.keySetCache[set] = *keys
			m.keySetCacheMu.Unlock()
		} else if !errors.Is(err, x.ErrNotFound) {
			return nil, err
		}
	}
	return &jwks, nil
}

// DeleteKey never deletes keys on Hardware Security Module. It returns x.ErrNotFound if the key does not exist on Hardware
// Security Module, so that keys stored in software key manager can still be deleted, and ErrPreGeneratedKeys otherwise.
func (m *KeyManager) DeleteKey(ctx context.Context, set, kid string) error {
	_, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "hsm.DeleteKey")
	defer span.End()
	attrs := map[string]string{
		"set": set,
		"kid": kid,
	}
	span.SetAttributes(otelx.StringAttrs(attrs)...)

	keyPair, err := m.FindKeyPair([]byte(kid), []byte(m.prefixKeySet(set)))
	if err != nil {
		return err
	}

	if keyPair == nil {
		return errors.WithStack(x.ErrNotFound)
	}

	return errors.WithStack(ErrPreGeneratedKeys)
}

// DeleteKeySet never deletes keys on Hardware Security Module. It returns x.ErrNotFound if the key set does not exist on
// Hardware Security Module, so that key sets stored in software key manager can still be deleted, and ErrPreGeneratedKeys
// otherwise.
func (m *KeyManager) DeleteKeySet(ctx context.Context, set string) error {
	_, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "hsm.DeleteKeySet")
	defer span.End()
	attrs := map[string]string{
		"set": set,
	}
	span.SetAttributes(otelx.StringAttrs(attrs)...)

	keyPairs, err := m.FindKeyPairs(nil, []byte(m.prefixKeySet(set)))
	if err != nil {
		return err
	}

	if keyPairs == nil {
		return errors.WithStack(x.ErrNotFound)
	}

	return errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) AddKey(_ context.Context, _ string, _ *jose.JSONWebKey) error {
	return errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) AddKeySet(_ context.Context, _ string, _ *jose.JSONWebKeySet) error {
	return errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) UpdateKey(_ context.Context, _ string, _ *jose.JSONWebKey) error {
	return errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) UpdateKeySet(_ context.Context, _ string, _ *jose.JSONWebKeySet) error {
	return errors.WithStack(ErrPreGeneratedKeys)
}

func (m *KeyManager) Close(_ context.Context) error {
	err := m.Context.Close()
	if err != nil {
		return err
	}
	return nil
}

func (m *KeyManager) getKeySetAttributes(ctx context.Context, key crypto11.Signer, kid []byte) (string, string, string, error) {
	if kid == nil {
		ckaId, err := m.GetAttribute(key, crypto11.CkaId)
		if err != nil {
			return "", "", "", err
		}
		kid = ckaId.Value
	}

	var alg string
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		alg = "RS256"
		if k.N.BitLen() < 4096 && !m.c.IsDevelopmentMode(ctx) {
			return "", "", "", errors.WithStack(jwk.ErrMinimalRsaKeyLength)
		}
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P521() {
			alg = "ES512"
		} else if k.Curve == elliptic.P256() {
			alg = "ES256"
		} else {
			return "", "", "", errors.WithStack(jwk.ErrUnsupportedEllipticCurve)
		}
	default:
		return "", "", "", errors.WithStack(jwk.ErrUnsupportedKeyAlgorithm)
	}

	use := "sig"
	ckaDecrypt, _ := m.GetAttribute(key, crypto11.CkaDecrypt)
	if ckaDecrypt != nil && len(ckaDecrypt.Value) != 0 && ckaDecrypt.Value[0] == 0x1 {
		use = "enc"
	}
	return string(kid), alg, use, nil
}

func createKeySet(key crypto11.Signer, kid, alg, use string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: createKeys(key, kid, alg, use),
	}
}

func createKeys(key crypto11.Signer, kid, alg, use string) []jose.JSONWebKey {
	return []jose.JSONWebKey{{
		Algorithm:                   alg,
		Use:                         use,
		Key:                         cryptosigner.Opaque(key),
		KeyID:                       kid,
		Certificates:                []*x509.Certificate{},
		CertificateThumbprintSHA1:   []uint8{},
		CertificateThumbprintSHA256: []uint8{},
	}}
}

func (m *KeyManager) prefixKeySet(set string) string {
	return fmt.Sprintf("%s%s", m.c.HSMKeySetPrefix(), set)
}
