{-# LANGUAGE FlexibleInstances #-}

module DNS.StateBinary.SPut (
  -- * Builder
    SPut
  , runSPut
  -- ** Basic builders
  , put8
  , put16
  , put32
  , putInt8
  , putInt16
  , putInt32
  , putShortByteString
  , putLenShortByteString
  , putReplicate
  -- ** Lower utilities
  , unexpectedSized
  -- ** Builder state
  , BState
  , builderPosition
  , addBuilderPosition
  , pushPointer
  , popPointer
  , appendBuilder
  -- ** Re-exports (fixme)
  , State
  , ST.modify
  , ST.execState
  ) where

import Control.Monad.State.Strict (State)
import qualified Control.Monad.State.Strict as ST
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC8
import qualified Data.ByteString.Short as Short
import Data.Map (Map)
import qualified Data.Map as M

import DNS.StateBinary.Types
import DNS.Types.Imports

----------------------------------------------------------------

-- | Builder type
type SPut a = State BState a

runSPut :: SPut () -> ByteString
runSPut sput = toBS $ bstBuilder $ run sput
  where
    run x = ST.execState x initialBState
    toBS = LC8.toStrict . BB.toLazyByteString

----------------------------------------------------------------

-- | Builder state
data BState = BState {
    bstDomain   :: Map RawDomain Int
  , bstPosition :: Int
  , bstBuilder  :: Builder
}

initialBState :: BState
initialBState = BState M.empty 0 mempty

----------------------------------------------------------------

builderPosition :: State BState Int
builderPosition = ST.gets bstPosition

addBuilderPosition :: Int -> State BState ()
addBuilderPosition n = do
    BState m cur b <- ST.get
    ST.put $ BState m (cur+n) b

popPointer :: RawDomain -> State BState (Maybe Int)
popPointer dom = ST.gets (M.lookup dom . bstDomain)

pushPointer :: RawDomain -> Int -> State BState ()
pushPointer dom pos = do
    BState m cur b <- ST.get
    ST.put $ BState (M.insert dom pos m) cur b

appendBuilder :: Builder -> State BState ()
appendBuilder bb = do
    BState m cur b <- ST.get
    ST.put $ BState m cur (b <> bb)

----------------------------------------------------------------

fixedSized :: Int -> (a -> Builder) -> a -> SPut ()
fixedSized n f v = do
    addBuilderPosition n
    appendBuilder $ f v

put8 :: Word8 -> SPut ()
put8 = fixedSized 1 BB.word8

put16 :: Word16 -> SPut ()
put16 = fixedSized 2 BB.word16BE

put32 :: Word32 -> SPut ()
put32 = fixedSized 4 BB.word32BE

putInt8 :: Int -> SPut ()
putInt8 = fixedSized 1 (BB.int8 . fromIntegral)

putInt16 :: Int -> SPut ()
putInt16 = fixedSized 2 (BB.int16BE . fromIntegral)

putInt32 :: Int -> SPut ()
putInt32 = fixedSized 4 (BB.int32BE . fromIntegral)

putReplicate :: Int -> Word8 -> SPut ()
putReplicate n w =
    fixedSized n BB.lazyByteString $ LB.replicate (fromIntegral n) w

----------------------------------------------------------------

expectedSized :: (a -> Int) -> (a -> Builder) -> a -> SPut ()
expectedSized n f v = do
    addBuilderPosition $ n v
    appendBuilder $ f v

putShortByteString :: ShortByteString -> SPut ()
putShortByteString = expectedSized Short.length BB.shortByteString

-- In the case of the TXT record, we need to put the string length
putLenShortByteString :: ShortByteString -> SPut ()
putLenShortByteString txt = do
    putInt8 len
    putShortByteString txt
   where
     len = fromIntegral $ Short.length txt

----------------------------------------------------------------

unexpectedSized :: (Int -> SPut ()) -> SPut () -> SPut ()
unexpectedSized p s = do
    let bs = runSPut s
    p $ BS.length bs
    s

