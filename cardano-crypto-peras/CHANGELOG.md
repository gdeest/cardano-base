# Changelog for `cardano-crypto-peras`

## 0.2.0.0

* Add the Peras certificate types
* Remove the placeholder `BoostedBlock`; rename `pcBostedBlock` to `pcBoostedBlock`
* Remove all `ToCBOR`/`FromCBOR` instances and the `decodeRecordOfSize` helper: this
  package no longer depends on `cardano-binary` for serialisation, matching
  `cardano-crypto-leios`; `EncCBOR`/`DecCBOR` instances are provided by
  `cardano-ledger-binary` instead
* Change `PerasRoundNo`'s representation from `Word64` to `Word32`
* Add `Cardano.Crypto.Peras.Vote` (`PerasVote`, `PerasVoteEligibilityProof`)
* Add `PerasCertSize` and `perasCertSizeUpperBound` to `Cardano.Crypto.Peras.Cert`

### `testlib`

* Add `Test.Cardano.Crypto.Peras.Gen`
* Add `genPerasVote`, `genPerasVoteEligibilityProof`

## 0.1.0.0

* Initial version released on [CHaP](https://github.com/input-output-hk/cardano-haskell-packages)
