// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build hsm
// +build hsm

package hsm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/x/contextx"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/persistence/sql"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"

	"github.com/ThalesIgnite/crypto11"
	"github.com/golang/mock/gomock"
	"github.com/miekg/pkcs11"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"

	"github.com/ory/hydra/v2/hsm"
	"github.com/ory/hydra/v2/x"
)

func TestDefaultKeyManager_HSMEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockHsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation())
	c.MustSet(context.Background(), config.KeyDSN, "memory")
	c.MustSet(context.Background(), config.HSMEnabled, "true")
	reg := driver.NewRegistrySQL()
	reg.WithLogger(l)
	reg.WithConfig(c)
	reg.WithHsmContext(mockHsmContext)
	err := reg.Init(context.Background(), false, true, &contextx.TestContextualizer{})
	assert.NoError(t, err)
	assert.IsType(t, &jwk.ManagerStrategy{}, reg.KeyManager())
	assert.IsType(t, &sql.Persister{}, reg.SoftwareKeyManager())
}

func TestKeyManager_HsmKeySetPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation(), configx.WithValue(config.HSMKeySetCacheTTL, "0s"))
	keySetPrefix := "application_specific_prefix."
	c.MustSet(context.Background(), config.HSMKeySetPrefix, keySetPrefix)
	m := hsm.NewKeyManager(hsmContext, c)

	rsaKey3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	rsaKey4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	rsaKeyPair3072 := NewMockSignerDecrypter(ctrl)
	rsaKeyPair3072.EXPECT().Public().Return(&rsaKey3072.PublicKey).AnyTimes()

	rsaKeyPair4096 := NewMockSignerDecrypter(ctrl)
	rsaKeyPair4096.EXPECT().Public().Return(&rsaKey4096.PublicKey).AnyTimes()

	ecdsaKeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaKeyPair.EXPECT().Public().Return(&ecdsaKey.PublicKey).AnyTimes()

	var kid = uuid.New()

	expectedPrefixedOpenIDConnectKeyName := fmt.Sprintf("%s%s", keySetPrefix, x.OpenIDConnectKeyName)

	t.Run("case=GetKey", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return(rsaKeyPair4096, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair4096), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)

		got, err := m.GetKey(context.TODO(), x.OpenIDConnectKeyName, kid)

		assert.NoError(t, err)
		expectedKeySet := expectedKeySet(rsaKeyPair4096, kid, "RS256", "sig")
		if !reflect.DeepEqual(got, expectedKeySet) {
			t.Errorf("GetKey() got = %v, want %v", got, expectedKeySet)
		}
	})
	t.Run("case=GetKeyMinimalRsaKeyLengthError", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return(rsaKeyPair3072, nil)

		_, err := m.GetKey(context.TODO(), x.OpenIDConnectKeyName, kid)

		assert.ErrorIs(t, err, jwk.ErrMinimalRsaKeyLength)
	})
	t.Run("case=GetKeySet", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return([]crypto11.Signer{rsaKeyPair4096}, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair4096), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair4096), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)

		got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)

		assert.NoError(t, err)
		expectedKeySet := expectedKeySet(rsaKeyPair4096, kid, "RS256", "sig")
		if !reflect.DeepEqual(got, expectedKeySet) {
			t.Errorf("GetKey() got = %v, want %v", got, expectedKeySet)
		}
	})
	t.Run("case=GetKeySetMinimalRsaKeyLengthError", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return([]crypto11.Signer{rsaKeyPair3072}, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair3072), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil)

		_, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)

		assert.ErrorIs(t, err, jwk.ErrMinimalRsaKeyLength)
	})
	t.Run("case=DeleteKey", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return(rsaKeyPair4096, nil)

		err := m.DeleteKey(context.TODO(), x.OpenIDConnectKeyName, kid)

		assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
	})
	t.Run("case=DeleteKeySet", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(expectedPrefixedOpenIDConnectKeyName))).Return([]crypto11.Signer{rsaKeyPair4096}, nil)

		err := m.DeleteKeySet(context.TODO(), x.OpenIDConnectKeyName)

		assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
	})
}

func TestKeyManager_GenerateAndPersistKeySet(t *testing.T) {
	m := &hsm.KeyManager{
		Context: nil,
	}
	got, err := m.GenerateAndPersistKeySet(context.TODO(), x.OpenIDConnectKeyName, uuid.New(), "RS256", "sig")
	assert.Nil(t, got)
	assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
}

func TestKeyManager_GetKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation())
	m := hsm.NewKeyManager(hsmContext, c)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	rsaKeyPair := NewMockSignerDecrypter(ctrl)
	rsaKeyPair.EXPECT().Public().Return(&rsaKey.PublicKey).AnyTimes()

	ecdsaP256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaP256KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP256KeyPair.EXPECT().Public().Return(&ecdsaP256Key.PublicKey).AnyTimes()

	ecdsaP521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	ecdsaP521KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP521KeyPair.EXPECT().Public().Return(&ecdsaP521Key.PublicKey).AnyTimes()

	ecdsaP224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	ecdsaP224KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP224KeyPair.EXPECT().Public().Return(&ecdsaP224Key.PublicKey).AnyTimes()

	var kid = uuid.New()

	type args struct {
		ctx context.Context
		set string
		kid string
	}
	tests := []struct {
		name       string
		setup      func(t *testing.T)
		args       args
		want       *jose.JSONWebKeySet
		wantErrMsg string
		wantErr    error
	}{
		{
			name: "Get RS256 sig",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(rsaKeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
			},
			want: expectedKeySet(rsaKeyPair, kid, "RS256", "sig"),
		},
		{
			name: "Get RS256 enc",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(rsaKeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true), nil)
			},
			want: expectedKeySet(rsaKeyPair, kid, "RS256", "enc"),
		},
		{
			name: "Key usage attribute error",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(rsaKeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, errors.New("GetAttributeError"))
			},
			want: expectedKeySet(rsaKeyPair, kid, "RS256", "sig"),
		},
		{
			name: "Get ES256 sig",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(ecdsaP256KeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP256KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
			},
			want: expectedKeySet(ecdsaP256KeyPair, kid, "ES256", "sig"),
		},
		{
			name: "Get ES256 enc",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(ecdsaP256KeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP256KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true), nil)
			},
			want: expectedKeySet(ecdsaP256KeyPair, kid, "ES256", "enc"),
		},
		{
			name: "Get ES512 sig",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(ecdsaP521KeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP521KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
			},
			want: expectedKeySet(ecdsaP521KeyPair, kid, "ES512", "sig"),
		},
		{
			name: "Get ES512 enc",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(ecdsaP521KeyPair, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP521KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true), nil)
			},
			want: expectedKeySet(ecdsaP521KeyPair, kid, "ES512", "enc"),
		},
		{
			name: "Key not found",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil)
			},
			wantErrMsg: "Not Found",
		},
		{
			name: "FindKeyPair Error",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errors.New("FindKeyPairError"))
			},
			wantErrMsg: "FindKeyPairError",
		},
		{
			name: "Unsupported elliptic curve",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
				kid: kid,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(ecdsaP224KeyPair, nil)
			},
			wantErr: errors.WithStack(jwk.ErrUnsupportedEllipticCurve),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			got, err := m.GetKey(tt.args.ctx, tt.args.set, tt.args.kid)
			if tt.wantErr != nil {
				require.Nil(t, got)
				require.IsType(t, tt.wantErr, err)
			} else if len(tt.wantErrMsg) != 0 {
				require.Nil(t, got)
				require.EqualError(t, err, tt.wantErrMsg)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyManager_GetKeySet(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation(), configx.WithValue(config.HSMKeySetCacheTTL, "0s"))
	m := hsm.NewKeyManager(hsmContext, c)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	rsaKid := uuid.New()
	rsaKeyPair := NewMockSignerDecrypter(ctrl)
	rsaKeyPair.EXPECT().Public().Return(&rsaKey.PublicKey).AnyTimes()

	ecdsaP256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaP256Kid := uuid.New()
	ecdsaP256KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP256KeyPair.EXPECT().Public().Return(&ecdsaP256Key.PublicKey).AnyTimes()

	ecdsaP521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	ecdsaP521Kid := uuid.New()
	ecdsaP521KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP521KeyPair.EXPECT().Public().Return(&ecdsaP521Key.PublicKey).AnyTimes()

	ecdsaP224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	ecdsaP224Kid := uuid.New()
	ecdsaP224KeyPair := NewMockSignerDecrypter(ctrl)
	ecdsaP224KeyPair.EXPECT().Public().Return(&ecdsaP224Key.PublicKey).AnyTimes()

	allKeys := []crypto11.Signer{rsaKeyPair, ecdsaP256KeyPair, ecdsaP521KeyPair}

	var keys []jose.JSONWebKey
	keys = append(keys, createJSONWebKeys(rsaKeyPair, rsaKid, "RS256", "sig")...)
	keys = append(keys, createJSONWebKeys(ecdsaP256KeyPair, ecdsaP256Kid, "ES256", "sig")...)
	keys = append(keys, createJSONWebKeys(ecdsaP521KeyPair, ecdsaP521Kid, "ES512", "sig")...)

	type args struct {
		ctx context.Context
		set string
	}
	tests := []struct {
		name       string
		setup      func(t *testing.T)
		args       args
		want       *jose.JSONWebKeySet
		wantErrMsg string
		wantErr    error
	}{
		{
			name: "With multiple keys per set",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(allKeys, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(rsaKid)), nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP256KeyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(ecdsaP256Kid)), nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP256KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP521KeyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(ecdsaP521Kid)), nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP521KeyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
			},
			want: &jose.JSONWebKeySet{Keys: keys},
		},
		{
			name: "GetCkaIdAttributeError Error",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(allKeys, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(rsaKeyPair), gomock.Eq(crypto11.CkaId)).Return(nil, errors.New("GetCkaIdAttributeError"))
			},
			wantErrMsg: "GetCkaIdAttributeError",
		},
		{
			name: "Key set not found",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil)
			},
			wantErrMsg: "Not Found",
		},
		{
			name: "FindKeyPairs Error",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errors.New("FindKeyPairsError"))
			},
			wantErrMsg: "FindKeyPairsError",
		},
		{
			name: "Unsupported elliptic curve",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{ecdsaP224KeyPair}, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(ecdsaP224KeyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(ecdsaP224Kid)), nil)
			},
			wantErr: errors.WithStack(jwk.ErrUnsupportedEllipticCurve),
		},
		{
			name: "Invalid key type Error",
			args: args{
				ctx: context.TODO(),
				set: x.OpenIDConnectKeyName,
			},
			setup: func(t *testing.T) {
				keyPair := NewMockSignerDecrypter(ctrl)
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{keyPair}, nil)
				hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(rsaKid)), nil)
				keyPair.EXPECT().Public().Return(nil).Times(1)
			},
			wantErr: errors.WithStack(jwk.ErrUnsupportedKeyAlgorithm),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			got, err := m.GetKeySet(tt.args.ctx, tt.args.set)
			if tt.wantErr != nil {
				require.Nil(t, got)
				require.IsType(t, tt.wantErr, err)
			} else if len(tt.wantErrMsg) != 0 {
				require.Nil(t, got)
				require.EqualError(t, err, tt.wantErrMsg)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyManager_GetKeySetCache(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	kid := uuid.New()

	setup := func(t *testing.T, ttl string) (*hsm.KeyManager, *MockContext, *MockSignerDecrypter, *time.Time) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		hsmContext := NewMockContext(ctrl)
		keyPair := NewMockSignerDecrypter(ctrl)
		keyPair.EXPECT().Public().Return(&rsaKey.PublicKey).AnyTimes()
		c := config.MustNew(context.Background(), logrusx.New("", ""), configx.SkipValidation())
		if ttl != "" {
			c.MustSet(context.Background(), config.HSMKeySetCacheTTL, ttl)
		}
		m := hsm.NewKeyManager(hsmContext, c)
		now := time.Now()
		m.SetNow(func() time.Time { return now })
		return m, hsmContext, keyPair, &now
	}
	expectRead := func(hsmContext *MockContext, keyPair *MockSignerDecrypter, times int) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{keyPair}, nil).Times(times)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil).Times(times)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil).Times(times)
	}

	t.Run("case=cached for 5 minutes by default", func(t *testing.T) {
		m, hsmContext, keyPair, now := setup(t, "")
		expectRead(hsmContext, keyPair, 1)

		_, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		*now = now.Add(5*time.Minute - time.Second)
		_, err = m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)

		expectRead(hsmContext, keyPair, 1)
		*now = now.Add(time.Second)
		_, err = m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
	})

	t.Run("case=disabled with 0s", func(t *testing.T) {
		m, hsmContext, keyPair, _ := setup(t, "0s")
		expectRead(hsmContext, keyPair, 2)

		for i := 0; i < 2; i++ {
			got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
			require.NoError(t, err)
			assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
		}
	})

	t.Run("case=cached until ttl expires", func(t *testing.T) {
		m, hsmContext, keyPair, now := setup(t, "1m")
		expectRead(hsmContext, keyPair, 1)

		for i := 0; i < 2; i++ {
			got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
			require.NoError(t, err)
			assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
		}

		*now = now.Add(59 * time.Second)
		_, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)

		expectRead(hsmContext, keyPair, 1)
		*now = now.Add(time.Second)
		got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
	})

	t.Run("case=errors are not cached", func(t *testing.T) {
		m, hsmContext, keyPair, _ := setup(t, "1m")
		gomock.InOrder(
			hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errors.New("hsm error")),
			hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil),
			hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{keyPair}, nil),
		)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)

		_, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		assert.EqualError(t, err, "hsm error")
		_, err = m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		assert.ErrorIs(t, err, x.ErrNotFound)
		got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
	})

	t.Run("case=modifying returned key set does not modify cache", func(t *testing.T) {
		m, hsmContext, keyPair, _ := setup(t, "1m")
		expectRead(hsmContext, keyPair, 1)

		got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		got.Keys[0].KeyID = "modified"
		got.Keys = append(got.Keys, got.Keys[0])

		got, err = m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
		got.Keys[0].KeyID = "modified"

		got, err = m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(keyPair, kid, "RS256", "sig"), got)
	})

	t.Run("case=cached per key set", func(t *testing.T) {
		m, hsmContext, keyPair, _ := setup(t, "1m")
		expectRead(hsmContext, keyPair, 1)
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OAuth2JWTKeyName))).Return(nil, nil).Times(2)

		for i := 0; i < 2; i++ {
			_, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
			require.NoError(t, err)
			_, err = m.GetKeySet(context.TODO(), x.OAuth2JWTKeyName)
			assert.ErrorIs(t, err, x.ErrNotFound)
		}
	})
}

func TestKeyManager_DeleteKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation())
	m := hsm.NewKeyManager(hsmContext, c)

	rsaKeyPair := NewMockSignerDecrypter(ctrl)

	kid := uuid.New()

	tests := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr error
	}{
		{
			name: "Existing key",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(rsaKeyPair, nil)
			},
			wantErr: hsm.ErrPreGeneratedKeys,
		},
		{
			name: "Key not found",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil)
			},
			wantErr: x.ErrNotFound,
		},
		{
			name: "FindKeyPair Error",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPair(gomock.Eq([]byte(kid)), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errFindKeyPair)
			},
			wantErr: errFindKeyPair,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			err := m.DeleteKey(context.TODO(), x.OpenIDConnectKeyName, kid)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestKeyManager_DeleteKeySet(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation())
	m := hsm.NewKeyManager(hsmContext, c)

	rsaKeyPair := NewMockSignerDecrypter(ctrl)

	tests := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr error
	}{
		{
			name: "Existing key set",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{rsaKeyPair}, nil)
			},
			wantErr: hsm.ErrPreGeneratedKeys,
		},
		{
			name: "Key set not found",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil)
			},
			wantErr: x.ErrNotFound,
		},
		{
			name: "FindKeyPairs Error",
			setup: func(t *testing.T) {
				hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errFindKeyPair)
			},
			wantErr: errFindKeyPair,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			err := m.DeleteKeySet(context.TODO(), x.OpenIDConnectKeyName)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

var errFindKeyPair = errors.New("FindKeyPairError")

func TestKeyManager_AddKey(t *testing.T) {
	m := &hsm.KeyManager{
		Context: nil,
	}
	err := m.AddKey(context.TODO(), x.OpenIDConnectKeyName, &jose.JSONWebKey{})
	assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
}

func TestKeyManager_AddKeySet(t *testing.T) {
	m := &hsm.KeyManager{
		Context: nil,
	}
	err := m.AddKeySet(context.TODO(), x.OpenIDConnectKeyName, &jose.JSONWebKeySet{})
	assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
}

func TestKeyManager_UpdateKey(t *testing.T) {
	m := &hsm.KeyManager{
		Context: nil,
	}
	err := m.UpdateKey(context.TODO(), x.OpenIDConnectKeyName, &jose.JSONWebKey{})
	assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
}

func TestKeyManager_UpdateKeySet(t *testing.T) {
	m := &hsm.KeyManager{
		Context: nil,
	}
	err := m.UpdateKeySet(context.TODO(), x.OpenIDConnectKeyName, &jose.JSONWebKeySet{})
	assert.ErrorIs(t, err, hsm.ErrPreGeneratedKeys)
}

func TestKeyManager_GetWellKnownKeySet(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation(), configx.WithValue(config.KeyDevelopmentMode, true))
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	openIDConnectKey := NewMockSignerDecrypter(ctrl)
	openIDConnectKey.EXPECT().Public().Return(&rsaKey2.PublicKey).AnyTimes()
	oAuth2JWTKey := NewMockSignerDecrypter(ctrl)
	oAuth2JWTKey.EXPECT().Public().Return(&rsaKey1.PublicKey).AnyTimes()
	var openIDConnectKeyId = uuid.New()
	var oAuth2JWTKeyId = uuid.New()
	expectedKeySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Algorithm:                   "RS256",
		Use:                         "sig",
		Key:                         openIDConnectKey.Public(),
		KeyID:                       openIDConnectKeyId,
		Certificates:                []*x509.Certificate{},
		CertificateThumbprintSHA1:   []uint8{},
		CertificateThumbprintSHA256: []uint8{},
	},
		{
			Algorithm:                   "RS256",
			Use:                         "sig",
			Key:                         oAuth2JWTKey.Public(),
			KeyID:                       oAuth2JWTKeyId,
			Certificates:                []*x509.Certificate{},
			CertificateThumbprintSHA1:   []uint8{},
			CertificateThumbprintSHA256: []uint8{},
		}}}
	m := hsm.NewKeyManager(hsmContext, c)

	t.Run("case=GetWellKnownKeySet cache miss", func(t *testing.T) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{openIDConnectKey}, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(openIDConnectKey), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(openIDConnectKeyId)), nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(openIDConnectKey), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)

		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OAuth2JWTKeyName))).Return([]crypto11.Signer{oAuth2JWTKey}, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(oAuth2JWTKey), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(oAuth2JWTKeyId)), nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(oAuth2JWTKey), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)

		got, err := m.GetWellKnownKeys(context.TODO())

		assert.NoError(t, err)
		assert.Len(t, got.Keys, 2)
		if !reflect.DeepEqual(got, expectedKeySet) {
			t.Errorf("GetKey() got = %v, want %v", got, expectedKeySet)
		}
	})
	t.Run("case=GetWellKnownKeySet cache hit", func(t *testing.T) {
		got, err := m.GetWellKnownKeys(context.TODO())

		assert.NoError(t, err)
		assert.Len(t, got.Keys, 2)
		if !reflect.DeepEqual(got, expectedKeySet) {
			t.Errorf("GetKey() got = %v, want %v", got, expectedKeySet)
		}
	})
}

func TestKeyManager_GetWellKnownKeySetCacheDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation(), configx.WithValue(config.KeyDevelopmentMode, true))
	c.MustSet(context.Background(), config.HSMKeySetCacheTTL, "0s")
	m := hsm.NewKeyManager(hsmContext, c)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	keyPair := NewMockSignerDecrypter(ctrl)
	keyPair.EXPECT().Public().Return(&rsaKey.PublicKey).AnyTimes()
	kid := uuid.New()

	hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OAuth2JWTKeyName))).Return(nil, nil).Times(2)
	hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{keyPair}, nil).Times(2)
	hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil).Times(2)
	hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil).Times(2)

	for i := 0; i < 2; i++ {
		got, err := m.GetWellKnownKeys(context.TODO())
		require.NoError(t, err)
		assert.Len(t, got.Keys, 1)
		assert.Equal(t, kid, got.Keys[0].KeyID)
		assert.Equal(t, keyPair.Public(), got.Keys[0].Key)
	}
}

func TestKeyManager_GetWellKnownKeySetCacheTTL(t *testing.T) {
	ctrl := gomock.NewController(t)
	hsmContext := NewMockContext(ctrl)
	defer ctrl.Finish()
	l := logrusx.New("", "")
	c := config.MustNew(context.Background(), l, configx.SkipValidation(), configx.WithValue(config.KeyDevelopmentMode, true))
	c.MustSet(context.Background(), config.HSMKeySetCacheTTL, "1m")
	m := hsm.NewKeyManager(hsmContext, c)
	now := time.Now()
	m.SetNow(func() time.Time { return now })
	// Not found is never cached, so it is read on every request.
	hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OAuth2JWTKeyName))).Return(nil, nil).AnyTimes()

	oldRsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	oldKey := NewMockSignerDecrypter(ctrl)
	oldKey.EXPECT().Public().Return(&oldRsaKey.PublicKey).AnyTimes()
	oldKeyId := uuid.New()
	newRsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	newKey := NewMockSignerDecrypter(ctrl)
	newKey.EXPECT().Public().Return(&newRsaKey.PublicKey).AnyTimes()
	newKeyId := uuid.New()

	expectRead := func(keyPair *MockSignerDecrypter, kid string) {
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return([]crypto11.Signer{keyPair}, nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaId)).Return(pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)), nil)
		hsmContext.EXPECT().GetAttribute(gomock.Eq(keyPair), gomock.Eq(crypto11.CkaDecrypt)).Return(nil, nil)
	}
	expectedPublicKeySet := func(keyPair *MockSignerDecrypter, kid string) *jose.JSONWebKeySet {
		return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Algorithm:                   "RS256",
			Use:                         "sig",
			Key:                         keyPair.Public(),
			KeyID:                       kid,
			Certificates:                []*x509.Certificate{},
			CertificateThumbprintSHA1:   []uint8{},
			CertificateThumbprintSHA256: []uint8{},
		}}}
	}

	t.Run("case=read once and shared with GetKeySet", func(t *testing.T) {
		expectRead(oldKey, oldKeyId)

		for i := 0; i < 2; i++ {
			got, err := m.GetWellKnownKeys(context.TODO())
			require.NoError(t, err)
			assert.Equal(t, expectedPublicKeySet(oldKey, oldKeyId), got)
		}
		got, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(oldKey, oldKeyId, "RS256", "sig"), got)
	})

	t.Run("case=rotated key is served after ttl expires", func(t *testing.T) {
		now = now.Add(59 * time.Second)
		got, err := m.GetWellKnownKeys(context.TODO())
		require.NoError(t, err)
		assert.Equal(t, expectedPublicKeySet(oldKey, oldKeyId), got)

		expectRead(newKey, newKeyId)
		now = now.Add(time.Second)
		got, err = m.GetWellKnownKeys(context.TODO())
		require.NoError(t, err)
		assert.Equal(t, expectedPublicKeySet(newKey, newKeyId), got)
		signingKeys, err := m.GetKeySet(context.TODO(), x.OpenIDConnectKeyName)
		require.NoError(t, err)
		assert.Equal(t, expectedKeySet(newKey, newKeyId, "RS256", "sig"), signingKeys)
	})

	t.Run("case=errors are not cached", func(t *testing.T) {
		now = now.Add(time.Minute)
		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, errors.New("hsm error"))
		_, err := m.GetWellKnownKeys(context.TODO())
		assert.EqualError(t, err, "hsm error")

		hsmContext.EXPECT().FindKeyPairs(gomock.Nil(), gomock.Eq([]byte(x.OpenIDConnectKeyName))).Return(nil, nil)
		got, err := m.GetWellKnownKeys(context.TODO())
		require.NoError(t, err)
		assert.Empty(t, got.Keys)

		expectRead(newKey, newKeyId)
		got, err = m.GetWellKnownKeys(context.TODO())
		require.NoError(t, err)
		assert.Equal(t, expectedPublicKeySet(newKey, newKeyId), got)
	})
}

func expectedKeySet(keyPair *MockSignerDecrypter, kid, alg, use string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: createJSONWebKeys(keyPair, kid, alg, use)}
}

func createJSONWebKeys(keyPair *MockSignerDecrypter, kid string, alg string, use string) []jose.JSONWebKey {
	return []jose.JSONWebKey{{
		Algorithm:                   alg,
		Use:                         use,
		Key:                         cryptosigner.Opaque(keyPair),
		KeyID:                       kid,
		Certificates:                []*x509.Certificate{},
		CertificateThumbprintSHA1:   []uint8{},
		CertificateThumbprintSHA256: []uint8{},
	}}
}
