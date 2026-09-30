{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Crypto.Peras (spec) where

import Cardano.Crypto.DSIGN (deriveVerKeyDSIGN, signDSIGN, verifyDSIGN)
import Cardano.Crypto.Peras (
  PerasBoostedBlock (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasSigningKey,
 )
import Cardano.Crypto.Peras.Cert (
  PerasCert (..),
  mkPerasCertVoters,
  perasCertNumberOfNonPersistentVoters,
  perasCertNumberOfVoters,
  perasCertVoterSeats,
  perasCertVotersFromSeats,
 )
import Cardano.Slotting.Slot (WithOrigin (..))
import qualified Data.Bitmap as Bitmap
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import qualified Data.List.NonEmpty as NonEmpty
import Test.Cardano.Crypto.Peras.Gen (
  genPerasCertVoters,
  genPerasVRFOutput,
  perasSigningKeyFromSeedByte,
 )
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  forAll,
  vectorOf,
  (===),
 )

spec :: Spec
spec = do
  describe "PerasCertVoters" $ do
    prop "perasCertVotersFromSeats . perasCertVoterSeats" $
      forAll (genPerasCertVoters True) $ \v ->
        perasCertVotersFromSeats (perasCertVoterSeats v) === Right v
    prop "counts voters" $
      forAll (genPerasCertVoters True) $ \v ->
        let seats = perasCertVoterSeats v
         in (perasCertNumberOfVoters v, perasCertNumberOfNonPersistentVoters v)
              === (length seats, length (NonEmpty.filter ((/= Nothing) . snd) seats))
    prop "rejects a persistent voter after a non-persistent one" $
      forAll genPerasVRFOutput $ \vrf ->
        perasCertVotersFromSeats
          (NonEmpty.fromList [(PerasSeatIndex 0, Just vrf), (PerasSeatIndex 1, Nothing)])
          `shouldSatisfy` isLeft
    prop "rejects a duplicate seat index" $
      forAll genPerasVRFOutput $ \vrf ->
        perasCertVotersFromSeats
          (NonEmpty.fromList [(PerasSeatIndex 3, Nothing), (PerasSeatIndex 3, Just vrf)])
          `shouldSatisfy` isLeft
    it "rejects an empty bitmap" $
      mkPerasCertVoters (Bitmap.fromIndices 7 []) [] `shouldSatisfy` isLeft
    prop "rejects more VRF outputs than voters" $
      forAll (vectorOf 2 genPerasVRFOutput) $ \vrfs ->
        mkPerasCertVoters (Bitmap.fromIndices 7 [3]) vrfs `shouldSatisfy` isLeft

  describe "PerasCert" $ do
    it "the minimal certificate's signature verifies under its key" $
      verifyDSIGN
        ()
        (deriveVerKeyDSIGN minimalCertKey)
        minimalCertMessage
        (unPerasSignature (pcSignature minimalCert))
        `shouldBe` Right ()

minimalCert :: PerasCert
minimalCert =
  PerasCert
    { pcRoundNo = 0
    , pcBoostedBlock = PerasBoostedBlock Origin
    , pcVoters = either error id (mkPerasCertVoters (Bitmap.fromIndices 0 [0]) [])
    , pcSignature = PerasSignature (signDSIGN () minimalCertMessage minimalCertKey)
    }

minimalCertKey :: PerasSigningKey
minimalCertKey = perasSigningKeyFromSeedByte 0x2a

minimalCertMessage :: BS.ByteString
minimalCertMessage = "peras-golden-message"
