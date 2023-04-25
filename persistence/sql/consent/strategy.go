package consent

import "github.com/gobuffalo/pop/v6"

type ConsentSessionRevocationStrategy interface {
	Execute(c *pop.Connection, consentId string) (int, error)
}

type ConsentSessionDeleteStrategy struct {
	ConsentSessionRevocationStrategy
}

type ConsentSessionExpireStrategy struct {
	ConsentSessionRevocationStrategy
}

func (p *ConsentSessionDeleteStrategy) Execute(c *pop.Connection, consentId string) (int, error) {
	// Since we ON DELETE CASCADE, hydra_oauth2_consent_request_handled will be removed automagically.
	localCount, err := c.RawQuery("DELETE FROM hydra_oauth2_consent_request WHERE challenge = ?", consentId).ExecWithCount()
	return localCount, err
}

func (p *ConsentSessionExpireStrategy) Execute(c *pop.Connection, consentId string) (int, error) {
	localCount, err := c.RawQuery("UPDATE hydra_oauth2_consent_request_handled SET remember_for = EXTRACT(EPOCH FROM (NOW() - requested_at)) WHERE challenge = ?", consentId).ExecWithCount()
	return localCount, err
}
