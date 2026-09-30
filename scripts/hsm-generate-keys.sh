#!/bin/sh

# Generates the key sets required by Ory Hydra on a Hardware Security Module token. Ory Hydra does not generate keys on
# Hardware Security Module itself, so they have to exist before Ory Hydra is started. Used for tests and demo setups.
#
# Key sets are generated with CKA_LABEL=<hsm.key_set_prefix><key set name> and CKA_ID=<key set name>, which Ory Hydra uses
# as the key id.

set -eu

HSM_LIBRARY=${HSM_LIBRARY:-/usr/lib/softhsm/libsofthsm2.so}
HSM_TOKEN_LABEL=${HSM_TOKEN_LABEL:-hydra}
HSM_PIN=${HSM_PIN:-1234}
HSM_KEY_SET_PREFIX=${HSM_KEY_SET_PREFIX:-}

for set in hydra.openid.id-token hydra.jwt.access-token; do
  label="${HSM_KEY_SET_PREFIX}${set}"
  pkcs11-tool --module "$HSM_LIBRARY" --token-label "$HSM_TOKEN_LABEL" --login --pin "$HSM_PIN" \
    --keypairgen --key-type rsa:4096 --usage-sign \
    --label "$label" --id "$(printf '%s' "$set" | od -An -tx1 | tr -d ' \n')"
done
