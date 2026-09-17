{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Peras (spec) where

import Cardano.Binary (
  DecoderError,
  Encoding,
  FromCBOR (..),
  ToCBOR (..),
  decodeFull',
  encodeBreak,
  encodeBytes,
  encodeListLen,
  encodeListLenIndef,
  serialize',
 )
import Cardano.Crypto.DSIGN (deriveVerKeyDSIGN, signDSIGN, verifyDSIGN)
import Cardano.Crypto.Peras (
  PerasBlockRef (..),
  PerasBoostedBlock (..),
  PerasRoundNo (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasSigningKey,
  PerasVRFOutput,
  perasSignatureSize,
  perasSignatureToBytes,
 )
import Cardano.Crypto.Peras.Cert (
  PerasCert (..),
  PerasCertVoters (..),
  mkPerasCertVoters,
  perasCertNumberOfNonPersistentVoters,
  perasCertNumberOfVoters,
  perasCertVoterSeats,
  perasCertVotersFromSeats,
 )
import Cardano.Slotting.Slot (SlotNo (..), WithOrigin (..))
import qualified Data.Bitmap as Bitmap
import Data.Bits (setBit)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Short as SBS
import Data.Either (isLeft)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Word (Word16)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Cardano.Crypto.Peras.Gen (
  genBitmap,
  genPerasBlockRef,
  genPerasBoostedBlock,
  genPerasCert,
  genPerasCertVoters,
  genPerasRoundNo,
  genPerasSeatIndex,
  genPerasSignature,
  genPerasVRFOutput,
  generateWith,
  perasSigningKeyFromSeedByte,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Property,
  choose,
  counterexample,
  forAll,
  resize,
  tabulate,
  vectorOf,
  (===),
 )

spec :: Spec
spec = do
  describe "CBOR roundtrips" $ do
    prop "PerasRoundNo" $ forAll genPerasRoundNo roundTrip
    prop "PerasSeatIndex" $ forAll genPerasSeatIndex roundTrip
    prop "PerasBlockRef" $ forAll genPerasBlockRef roundTrip
    prop "PerasBoostedBlock" $ forAll genPerasBoostedBlock roundTrip
    prop "Bitmap" $ forAll genBitmap roundTrip
    prop "PerasSignature" $ forAll genPerasSignature roundTrip
    prop "PerasVRFOutput" $ forAll genPerasVRFOutput roundTrip
    prop "PerasCertVoters (persistent only)" $
      forAll (genPerasCertVoters False) $
        \v -> tabulateVoters v (roundTrip v)
    prop "PerasCertVoters" $
      forAll (genPerasCertVoters True) $
        \v -> tabulateVoters v (roundTrip v)
    prop "PerasCert (persistent only)" $
      forAll (genPerasCert False) $
        \c -> tabulateVoters (pcVoters c) (roundTrip c)
    prop "PerasCert" $
      forAll (genPerasCert True) $
        \c -> tabulateVoters (pcVoters c) (roundTrip c)

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

  describe "decoding rejects" $ do
    prop "a block hash that is not 32 bytes" $
      forAll (choose (0, 64)) $ \n ->
        forAll (genByteString (if n == 32 then 33 else n)) $ \h ->
          decodeAs @PerasBlockRef (encodeListLen 2 <> toCBOR (SlotNo 1) <> encodeBytes h)
            `shouldSatisfy` isLeft
    prop "a boosted block wrapped in a list of length 2" $
      forAll genPerasBlockRef $ \ref ->
        decodeAs @PerasBoostedBlock (encodeListLen 2 <> toCBOR ref <> toCBOR ref)
          `shouldSatisfy` isLeft
    it "voters with an empty bitmap" $
      decodeAs @PerasCertVoters
        (encodeListLen 2 <> toCBOR (Bitmap.fromIndices (15 :: Word16) []) <> toCBOR ([] :: [PerasVRFOutput]))
        `shouldSatisfy` isLeft
    it "voters whose bitmap has a bit set above its upper bound" $
      decodeAs @PerasCertVoters
        ( encodeListLen 2
            <> (encodeListLen 2 <> toCBOR (3 :: Word16) <> encodeBytes (BS.singleton (0 `setBit` 0 `setBit` 7)))
            <> toCBOR ([] :: [PerasVRFOutput])
        )
        `shouldSatisfy` isLeft
    prop "voters with more VRF outputs than set bits" $
      forAll (vectorOf 2 genPerasVRFOutput) $ \vrfs ->
        decodeAs @PerasCertVoters
          (encodeListLen 2 <> toCBOR (Bitmap.fromIndices (15 :: Word16) [4]) <> toCBOR vrfs)
          `shouldSatisfy` isLeft
    prop "random bytes as a signature" $
      forAll (genByteString (fromIntegral perasSignatureSize)) $ \bs ->
        decodeAs @PerasSignature (encodeBytes bs) `shouldSatisfy` isLeft
    prop "a certificate with three fields" $
      forAll (genPerasCert True) $ \c ->
        decodeAs @PerasCert
          (encodeListLen 3 <> toCBOR (pcRoundNo c) <> toCBOR (pcBoostedBlock c) <> toCBOR (pcVoters c))
          `shouldSatisfy` isLeft
    prop "accepts indefinite-length arrays everywhere" $
      forAll (genPerasCert True) $ \c ->
        let indef xs = encodeListLenIndef <> mconcat xs <> encodeBreak
            v = pcVoters c
            boosted = case unPerasBoostedBlock (pcBoostedBlock c) of
              Origin -> indef []
              At ref -> indef [indef [toCBOR (pbrSlot ref), encodeBytes (SBS.fromShort (pbrHash ref))]]
            bitmap = perasCertVotersBitmap v
         in decodeAs @PerasCert
              ( indef
                  [ toCBOR (pcRoundNo c)
                  , boosted
                  , indef
                      [ toCBOR bitmap
                      , indef (toCBOR <$> perasCertNonPersistentVRFOutputs v)
                      ]
                  , toCBOR (pcSignature c)
                  ]
              )
              === Right c
    prop "accepts a definite-length list of VRF outputs" $
      forAll (genPerasCertVoters True) $ \v ->
        decodeAs @PerasCertVoters
          ( encodeListLen 2
              <> toCBOR (perasCertVotersBitmap v)
              <> encodeListLen (fromIntegral (length (perasCertNonPersistentVRFOutputs v)))
              <> foldMap toCBOR (perasCertNonPersistentVRFOutputs v)
          )
          === Right v

  describe "fixed bytes" $ do
    it "encodes the minimal certificate to the recorded bytes" $
      B16.encode (serialize' minimalCert) `shouldBe` minimalCertHex
    it "decodes the recorded bytes to the minimal certificate" $
      case B16.decode minimalCertHex of
        Left err -> expectationFailure err
        Right bytes -> decodeFull' bytes `shouldBe` Right minimalCert
    it "the minimal certificate's signature verifies under its key" $
      verifyDSIGN
        ()
        (deriveVerKeyDSIGN minimalCertKey)
        minimalCertMessage
        (unPerasSignature (pcSignature minimalCert))
        `shouldBe` Right ()
    it "encodes the pinned certificate to the recorded bytes" $
      B16.encode (serialize' pinnedCert) `shouldBe` pinnedCertHex
    it "decodes the recorded bytes to the pinned certificate" $
      case B16.decode pinnedCertHex of
        Left err -> expectationFailure err
        Right bytes -> decodeFull' bytes `shouldBe` Right pinnedCert
    it "keeps the signature bytes of the pinned certificate" $
      BS.length (perasSignatureToBytes (pcSignature pinnedCert))
        `shouldBe` fromIntegral perasSignatureSize

roundTrip :: (Eq a, Show a, ToCBOR a, FromCBOR a) => a -> Property
roundTrip a =
  counterexample (show encoded) $
    decodeFull' encoded === Right a
  where
    encoded = serialize' a

decodeAs :: forall a. FromCBOR a => Encoding -> Either DecoderError a
decodeAs = decodeFull' . serialize'

tabulateVoters :: PerasCertVoters -> Property -> Property
tabulateVoters v =
  tabulate "voters" [bucket 50 (perasCertNumberOfVoters v)]
    . tabulate "non-persistent voters" [bucket 50 (perasCertNumberOfNonPersistentVoters v)]
  where
    bucket n x = show (x `div` n * n) <> "-" <> show (x `div` n * n + n)

minimalCert :: PerasCert
minimalCert =
  PerasCert
    { pcRoundNo = PerasRoundNo 0
    , pcBoostedBlock = PerasBoostedBlock Origin
    , pcVoters = either error id (mkPerasCertVoters (Bitmap.fromIndices 0 [0]) [])
    , pcSignature = PerasSignature (signDSIGN () minimalCertMessage minimalCertKey)
    }

minimalCertKey :: PerasSigningKey
minimalCertKey = perasSigningKeyFromSeedByte 0x2a

minimalCertMessage :: BS.ByteString
minimalCertMessage = "peras-golden-message"

minimalCertHex :: BS.ByteString
minimalCertHex =
  BS.concat
    [ "84" -- array(4)
    , "00" -- round 0
    , "80" -- boosted block: Origin = []
    , "82" -- voters: array(2)
    , "82004101" --   bitmap: [max index 0, h'01']
    , "9fff" --   no VRF outputs (indefinite-length empty list)
    , "5830" -- signature: bytes(48)
    , minimalCertSignatureHex
    ]

minimalCertSignatureHex :: BS.ByteString
minimalCertSignatureHex =
  BS.concat
    [ "b9df2ed101cabf936f97e854ff8b7234c6583017fd83e140"
    , "ece04dcab6aa398a0da4dc6ab47c9faf4e436424237865d9"
    ]

pinnedCert :: PerasCert
pinnedCert = resize 4 (genPerasCert True) `generateWith` (42 :: Int)

pinnedCertHex :: BS.ByteString
pinnedCertHex =
  BS.concat
    [ "8404818202582042286a7db9bd50745d9b8d4ba448af3b0a0da8f8ab3c71c23c"
    , "661cf3c15e1caf82820842f7019f58308fc043c27934404c58e67bd6182d36cf"
    , "762a742a88eb27dfa48f032b2f2d796306a0f3cf656dba88b467c332b961d510"
    , "583082b91c17dd4ca6657d1dc6f486959ba37af700c61856f384c7fa0c37b485"
    , "27613114bda06ea3c23fc8d6876bf32e93885830ad66a6a7da5c93b316cfb67e"
    , "8c9ca5696c8d0a8b3b8807ff2ccd13a150eaceab48e238ed7800356dc89044bf"
    , "0fae7d035830889e1fccc3933056998c557a719312a94365dbb4aa67efc843aa"
    , "23a2fd80920043665f3551ecfb9638c952669d44086458308ca13067d26167a7"
    , "112ee5302866cde3e805039b3f815dcd4bc07185ae0e73b36345c425470ab63d"
    , "52c0a5fdd848dc1dff5830a046b8531cf9ef6029a99f19cdeb9fc9f66fbab1fc"
    , "a93ea97165381a73e3064e0096cc362baee2ceb19717883f2a9ece"
    ]
