{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Crypto.Peras.Cert (
  PerasCertVoters (UnsafePerasCertVoters, perasCertVotersBitmap, perasCertNonPersistentVRFOutputs),
  mkPerasCertVoters,
  perasCertVotersFromSeats,
  perasCertVoterSeats,
  perasCertNumberOfVoters,
  perasCertNumberOfNonPersistentVoters,
  PerasCert (..),
  PerasRoundNo (..),
  PerasBoostedBlock (..),
  PerasSignature (..),
  PerasVRFOutput (..),
) where

import Cardano.Binary (
  FromCBOR (..),
  ToCBOR (..),
  decodeCollection,
  decodeListLenOrIndef,
  encodeListLen,
 )
import Cardano.Crypto.Peras (
  PerasBoostedBlock (..),
  PerasRoundNo (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasVRFOutput (..),
  decodeRecordOfSize,
 )
import Control.DeepSeq (NFData)
import Control.Monad (unless, when)
import Data.Bitmap (Bitmap)
import qualified Data.Bitmap as Bitmap
import Data.List (sortOn)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes, isJust, isNothing)
import Data.Word (Word16)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

{-------------------------------------------------------------------------------
   Voters
-------------------------------------------------------------------------------}

-- | Compact representation of the voters in a Peras certificate.
--
-- This compact representation consists of a bitmap of voter seat indices and a
-- list of non-persistent eligibility proofs (VRF outputs). In this setup, the
-- last @np@ indices in the bitmap that are flipped to 1 correspond to
-- non-persistent voters, where @np@ is the length of the list of non-persistent
-- eligibility proofs. The remaining flipped indices in the bitmap correspond
-- to persistent voters.
data PerasCertVoters = UnsafePerasCertVoters
  { perasCertVotersBitmap :: !(Bitmap Word16)
  , perasCertNonPersistentVRFOutputs :: ![PerasVRFOutput]
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

mkPerasCertVoters :: Bitmap Word16 -> [PerasVRFOutput] -> Either String PerasCertVoters
mkPerasCertVoters bitmap vrfOutputs = do
  let numVoters = Bitmap.numSetBits bitmap
      numProofs = length vrfOutputs
  when (numVoters == 0) $
    Left "Invalid Peras certificate: empty voters bitmap"
  when (numProofs > numVoters) $
    Left $
      unlines
        [ "Invalid Peras certificate:"
            <> " more non-persistent voter eligibility proofs were provided"
            <> " than the number of voters in the certificate"
        , " * number of voters: "
            <> show numVoters
        , " * number of proofs: "
            <> show numProofs
        ]
  pure (UnsafePerasCertVoters bitmap vrfOutputs)

perasCertVoterSeats :: PerasCertVoters -> NonEmpty (PerasSeatIndex, Maybe PerasVRFOutput)
perasCertVoterSeats UnsafePerasCertVoters {perasCertVotersBitmap, perasCertNonPersistentVRFOutputs} =
  case zip seats proofs of
    [] -> error "perasCertVoterSeats: empty voters bitmap (invariant violated via UnsafePerasCertVoters)"
    x : xs -> x :| xs
  where
    seats = PerasSeatIndex <$> Bitmap.toIndices perasCertVotersBitmap
    numPersistent = length seats - length perasCertNonPersistentVRFOutputs
    proofs = replicate numPersistent Nothing <> fmap Just perasCertNonPersistentVRFOutputs

perasCertVotersFromSeats ::
  NonEmpty (PerasSeatIndex, Maybe PerasVRFOutput) ->
  Either String PerasCertVoters
perasCertVotersFromSeats seats = do
  let sorted = sortOn fst (NonEmpty.toList seats)
      indices = unPerasSeatIndex . fst <$> sorted
      proofs = snd <$> sorted
  when (any (uncurry (==)) (zip indices (drop 1 indices))) $
    Left "Invalid Peras certificate voters: duplicate seat index"
  unless (all isJust (dropWhile isNothing proofs)) $
    Left "Invalid Peras certificate voters: persistent voter after a non-persistent one"
  let bitmap = Bitmap.fromIndices (last indices) indices
  mkPerasCertVoters bitmap (catMaybes proofs)

perasCertNumberOfVoters :: PerasCertVoters -> Int
perasCertNumberOfVoters = Bitmap.numSetBits . perasCertVotersBitmap

perasCertNumberOfNonPersistentVoters :: PerasCertVoters -> Int
perasCertNumberOfNonPersistentVoters = length . perasCertNonPersistentVRFOutputs

instance ToCBOR PerasCertVoters where
  toCBOR UnsafePerasCertVoters {perasCertVotersBitmap, perasCertNonPersistentVRFOutputs} =
    encodeListLen 2
      <> toCBOR perasCertVotersBitmap
      <> toCBOR perasCertNonPersistentVRFOutputs

instance FromCBOR PerasCertVoters where
  fromCBOR = decodeRecordOfSize "PerasCertVoters" 2 $ do
    bitmap <- fromCBOR
    vrfOutputs <- decodeCollection decodeListLenOrIndef fromCBOR
    either fail pure (mkPerasCertVoters bitmap vrfOutputs)

{-------------------------------------------------------------------------------
   Certificates
-------------------------------------------------------------------------------}

-- | Concrete Peras certificates using BLS signatures
data PerasCert = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !PerasSignature
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

instance ToCBOR PerasCert where
  toCBOR PerasCert {pcRoundNo, pcBoostedBlock, pcVoters, pcSignature} =
    encodeListLen 4
      <> toCBOR pcRoundNo
      <> toCBOR pcBoostedBlock
      <> toCBOR pcVoters
      <> toCBOR pcSignature

instance FromCBOR PerasCert where
  fromCBOR =
    decodeRecordOfSize "PerasCert" 4 $
      PerasCert
        <$> fromCBOR
        <*> fromCBOR
        <*> fromCBOR
        <*> fromCBOR
