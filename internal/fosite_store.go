package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ory/hydra/client"
	"github.com/ory/hydra/driver"
	"github.com/pkg/errors"
)

func AddFositeExamples(r driver.Registry) {
	hashedSecret, err := hashClientSecret("foobar")
	if err != nil {
		panic(err)
	}
	for _, c := range []client.Client{
		{
			OutfacingID:   "my-client",
			Secret:        hashedSecret,
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scope:         "fosite,openid,photos,offline",
		},
		{
			OutfacingID:   "encoded:client",
			Secret:        "encoded&password",
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scope:         "fosite,openid,photos,offline",
		},
	} {
		// #nosec G601
		if err := r.ClientManager().CreateClient(context.Background(), &c); err != nil {
			panic(err)
		}
	}
}

func hashClientSecret(clientSecret string) (string, error) {
	var err error
	hashedClientSecret := sha256.New()
	_, err = hashedClientSecret.Write([]byte(clientSecret))
	if err != nil {
		return "", errors.New("failed to create client secret hash")
	}
	sha256Hash := hex.EncodeToString(hashedClientSecret.Sum(nil))
	return sha256Hash, nil
}
