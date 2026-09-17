# cardano-crypto-peras

This package provides concrete definitions for the Peras-specific components
needed by layers other than Consensus:

- **Peras certificates**: these need to be stored in blocks in order to
  coordinate the end of a cooldown. Since this addition ultimately affects
  block sizes (and block size checks live in Ledger), the best place to store
  these certificates is at the Ledger level.

Types and `ToCBOR`/`FromCBOR` instances live in `Cardano.Crypto.Peras` and
`Cardano.Crypto.Peras.Cert`.
