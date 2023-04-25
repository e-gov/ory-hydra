// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package consent

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"

	"github.com/ory/x/sqlxx"
)

type ConsentSessionRevocationStrategy interface {
	Execute(c *pop.Connection, consentChallengeId sqlxx.NullString, networkId uuid.UUID) (int, error)
}

type ConsentSessionDeleteStrategy struct {
	ConsentSessionRevocationStrategy
}

type ConsentSessionExpireStrategy struct {
	ConsentSessionRevocationStrategy
}

func (p *ConsentSessionDeleteStrategy) Execute(c *pop.Connection, consentChallengeId sqlxx.NullString, networkId uuid.UUID) (int, error) {
	// Since we ON DELETE CASCADE, hydra_oauth2_consent_request_handled will be removed automagically.
	localCount, err := c.RawQuery("DELETE FROM hydra_oauth2_flow WHERE consent_challenge_id = ? AND nid = ?", consentChallengeId, networkId).ExecWithCount()
	return localCount, err
}

func (p *ConsentSessionExpireStrategy) Execute(c *pop.Connection, consentChallengeId sqlxx.NullString, networkId uuid.UUID) (int, error) {
	localCount, err := c.RawQuery("UPDATE hydra_oauth2_flow SET consent_remember_for = EXTRACT(EPOCH FROM (NOW() - requested_at AT TIME ZONE 'UTC')) WHERE consent_challenge_id = ? AND nid = ?", consentChallengeId, networkId).ExecWithCount()
	return localCount, err
}
