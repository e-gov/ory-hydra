// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/pkg/errors"
)

func AddFositeExamples(r driver.Registry) {
	hashedSecret, err := HashClientSecret("foobar")
	if err != nil {
		panic(err)
	}
	hashedSecretEncoded, err := HashClientSecret("encoded&password")
	if err != nil {
		panic(err)
	}
	for _, c := range []client.Client{
		{
			LegacyClientID: "my-client",
			Secret:         hashedSecret,
			RedirectURIs:   []string{"http://localhost:3846/callback"},
			ResponseTypes:  []string{"id_token", "code", "token"},
			GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scope:          "fosite,openid,photos,offline",
		},
		{
			LegacyClientID: "encoded:client",
			Secret:         hashedSecretEncoded,
			RedirectURIs:   []string{"http://localhost:3846/callback"},
			ResponseTypes:  []string{"id_token", "code", "token"},
			GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scope:          "fosite,openid,photos,offline",
		},
	} {
		// #nosec G601
		if err := r.ClientManager().CreateClient(context.Background(), &c); err != nil {
			panic(err)
		}
	}
}

func HashClientSecret(clientSecret string) (string, error) {
	var err error
	hashedClientSecret := sha256.New()
	_, err = hashedClientSecret.Write([]byte(clientSecret))
	if err != nil {
		return "", errors.New("failed to create client secret hash")
	}
	sha256Hash := hex.EncodeToString(hashedClientSecret.Sum(nil))
	return sha256Hash, nil
}
