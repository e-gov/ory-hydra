// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build hsm
// +build hsm

package hsm

import "time"

// SetNow replaces the clock used for key set cache expiry.
func (m *KeyManager) SetNow(now func() time.Time) {
	m.keySetCache.now = now
}
