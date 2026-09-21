{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.Peras (
  -- * Peras round numbers
  PerasRoundNo (..),
  onPerasRoundNo,
  PerasSeatIndex (..),
  maxPerasSeatIndex,
  PerasBlockRef (..),
  perasBlockHashSize,
  mkPerasBlockRef,
  PerasBoostedBlock (..),
  PerasDSIGN,
  PerasSigningKey,
  PerasVerificationKey,
  PerasSignature (..),
  PerasVRFOutput (..),
  perasSignatureSize,
  perasSignatureToBytes,
  perasVRFOutputToBytes,
  decodeRecordOfSize,
) where

import Cardano.Binary (
  Decoder,
  FromCBOR (..),
  ToCBOR (..),
  decodeBreakOr,
  decodeBytes,
  decodeListLenOrIndef,
  encodeBytes,
  encodeListLen,
  encodeMaybe,
 )
import Cardano.Binary.FixedSizeCodec (fixedSize, rawEncodeFixedSized)
import Cardano.Crypto.DSIGN (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN)
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN)
import Cardano.Slotting.Slot (SlotNo, WithOrigin, withOriginFromMaybe, withOriginToMaybe)
import Codec.Serialise (Serialise)
import Control.DeepSeq (NFData)
import Control.Monad (unless)
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SBS
import Data.Coerce (coerce)
import Data.Ord (comparing)
import Data.Proxy (Proxy (..))
import Data.Word (Word16, Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import Quiet (Quiet (..))

{-------------------------------------------------------------------------------
   Peras round numbers
-------------------------------------------------------------------------------}

-- | Round number in a Peras election.
newtype PerasRoundNo = PerasRoundNo {unPerasRoundNo :: Word64}
  deriving (Show) via Quiet PerasRoundNo
  deriving stock (Generic)
  deriving newtype (Enum, Eq, Ord, Num, Bounded, NoThunks, NFData, Serialise, ToCBOR, FromCBOR)

-- | Lift a binary operation on 'Word64' to 'PerasRoundNo'
onPerasRoundNo ::
  (Word64 -> Word64 -> Word64) ->
  (PerasRoundNo -> PerasRoundNo -> PerasRoundNo)
onPerasRoundNo = coerce

{-------------------------------------------------------------------------------
   Seat indices
-------------------------------------------------------------------------------}

-- | Seat index in the voting committee used for Peras
newtype PerasSeatIndex = PerasSeatIndex {unPerasSeatIndex :: Word16}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Enum, Bounded, NoThunks, NFData, ToCBOR, FromCBOR)

maxPerasSeatIndex :: PerasSeatIndex
maxPerasSeatIndex = maxBound

{-------------------------------------------------------------------------------
   Block references
-------------------------------------------------------------------------------}

data PerasBlockRef = PerasBlockRef
  { pbrSlot :: !SlotNo
  , pbrHash :: !ShortByteString
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

perasBlockHashSize :: Int
perasBlockHashSize = 32

mkPerasBlockRef :: SlotNo -> ShortByteString -> Maybe PerasBlockRef
mkPerasBlockRef slot hash
  | SBS.length hash == perasBlockHashSize = Just (PerasBlockRef slot hash)
  | otherwise = Nothing

instance ToCBOR PerasBlockRef where
  toCBOR (PerasBlockRef slot hash) =
    encodeListLen 2
      <> toCBOR slot
      <> encodeBytes (SBS.fromShort hash)

instance FromCBOR PerasBlockRef where
  fromCBOR = decodeRecordOfSize "PerasBlockRef" 2 $ do
    slot <- fromCBOR
    hash <- SBS.toShort <$> decodeBytes
    case mkPerasBlockRef slot hash of
      Just ref -> pure ref
      Nothing ->
        fail $
          "PerasBlockRef: expected a hash of "
            <> show perasBlockHashSize
            <> " bytes, got "
            <> show (SBS.length hash)

-- | The slot number and 32-byte hash of the block being voted for.
newtype PerasBoostedBlock = PerasBoostedBlock {unPerasBoostedBlock :: WithOrigin PerasBlockRef}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NoThunks, NFData)

instance ToCBOR PerasBoostedBlock where
  toCBOR = encodeMaybe toCBOR . withOriginToMaybe . unPerasBoostedBlock

instance FromCBOR PerasBoostedBlock where
  fromCBOR =
    PerasBoostedBlock . withOriginFromMaybe
      <$> ( decodeListLenOrIndef >>= \case
              Just 0 -> pure Nothing
              Just 1 -> Just <$> fromCBOR
              Just n -> fail $ "PerasBoostedBlock: expected 0 or 1 fields, got " <> show n
              Nothing ->
                decodeBreakOr >>= \case
                  True -> pure Nothing
                  False -> do
                    ref <- fromCBOR
                    done <- decodeBreakOr
                    unless done $ fail "PerasBoostedBlock: expected 0 or 1 fields"
                    pure (Just ref)
          )

{-------------------------------------------------------------------------------
   BLS cryptography
-------------------------------------------------------------------------------}

type PerasDSIGN = BLS12381MinSigDSIGN

type PerasSigningKey = SignKeyDSIGN PerasDSIGN

type PerasVerificationKey = VerKeyDSIGN PerasDSIGN

newtype PerasSignature = PerasSignature {unPerasSignature :: SigDSIGN PerasDSIGN}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NoThunks, NFData, ToCBOR, FromCBOR)

instance Ord PerasSignature where
  compare = comparing perasSignatureToBytes

newtype PerasVRFOutput = PerasVRFOutput {unPerasVRFOutput :: SigDSIGN PerasDSIGN}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NoThunks, NFData, ToCBOR, FromCBOR)

instance Ord PerasVRFOutput where
  compare = comparing perasVRFOutputToBytes

perasSignatureSize :: Word
perasSignatureSize = fixedSize (Proxy @(SigDSIGN PerasDSIGN))

perasSignatureToBytes :: PerasSignature -> ByteString
perasSignatureToBytes = rawEncodeFixedSized . unPerasSignature

perasVRFOutputToBytes :: PerasVRFOutput -> ByteString
perasVRFOutputToBytes = rawEncodeFixedSized . unPerasVRFOutput

{-------------------------------------------------------------------------------
   Decoding helpers
-------------------------------------------------------------------------------}

decodeRecordOfSize :: String -> Int -> Decoder s a -> Decoder s a
decodeRecordOfSize name size body =
  decodeListLenOrIndef >>= \case
    Just n
      | n == size -> body
      | otherwise ->
          fail $ name <> ": expected " <> show size <> " fields, got " <> show n
    Nothing -> do
      x <- body
      done <- decodeBreakOr
      unless done $ fail $ name <> ": expected " <> show size <> " fields"
      pure x
