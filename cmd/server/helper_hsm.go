// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/hsm"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/x"
)

// ensureHSMKeySets verifies that the key sets used for signing tokens exist on Hardware Security Module, because keys
// are not generated on Hardware Security Module.
func ensureHSMKeySets(ctx context.Context, d driver.Registry) error {
	sets := []string{x.OpenIDConnectKeyName}
	if d.Config().AccessTokenStrategy(ctx) == config.AccessTokenJWTStrategy {
		sets = append(sets, x.OAuth2JWTKeyName)
	}
	// Hardware Security Module is checked directly, as key manager falls back to software key manager.
	return jwk.EnsureKeySetsExist(ctx, hsm.NewKeyManager(d.HSMContext(), d.Config()), sets...)
}
