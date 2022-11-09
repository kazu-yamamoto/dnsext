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
  , with16Length
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
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Internal (ByteString(..))
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC8
import qualified Data.ByteString.Short as Short
import Data.Map (Map)
import qualified Data.Map as M
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (poke)
import System.IO.Unsafe (unsafePerformIO)

import DNS.StateBinary.Types
import DNS.Types.Imports

----------------------------------------------------------------

-- | Builder type
type SPut a = State BState a

runSPut :: SPut () -> ByteString
runSPut sput = let st = run sput
                   builder = bstBuilder st
                   fixLens = bstFixLen st
               in unsafeFixLen fixLens $ toBS builder
  where
    run x = ST.execState x initialBState
    toBS = LC8.toStrict . BB.toLazyByteString
    unsafeFixLen fls bs@(PS fptr off _) = unsafePerformIO $ do
        withForeignPtr fptr $ \p0 -> do
            let p = p0 `plusPtr` off
            mapM_ (fixL p) fls
        return bs
    fixL beg (pos,len) = do
        let (u0,l0) = len `divMod` 256
            u = fromIntegral u0 :: Word8
            l = fromIntegral l0 :: Word8
        poke (beg `plusPtr` pos) u
        poke (beg `plusPtr` (pos + 1)) l

----------------------------------------------------------------

type Position = Int

-- | Builder state
data BState = BState {
    bstDomain   :: Map RawDomain Int
  , bstPosition :: Position
  , bstBuilder  :: Builder
  , bstFixLen   :: [(Position, Int)]
}

initialBState :: BState
initialBState = BState M.empty 0 mempty []

----------------------------------------------------------------

builderPosition :: State BState Position
builderPosition = ST.gets bstPosition

addBuilderPosition :: Int -> State BState ()
addBuilderPosition n = do
    BState m cur b fl <- ST.get
    ST.put $ BState m (cur+n) b fl

popPointer :: RawDomain -> State BState (Maybe Int)
popPointer dom = ST.gets (M.lookup dom . bstDomain)

pushPointer :: RawDomain -> Int -> State BState ()
pushPointer dom pos = do
    BState m cur b fl <- ST.get
    ST.put $ BState (M.insert dom pos m) cur b fl

appendBuilder :: Builder -> State BState ()
appendBuilder bb = do
    BState m cur b fl <- ST.get
    ST.put $ BState m cur (b <> bb) fl

pushFixLen :: Position -> Int -> State BState ()
pushFixLen pos len = do
    BState m cur b fl <- ST.get
    ST.put $ BState m cur b $ (pos,len) : fl

----------------------------------------------------------------

fixedSized :: Int -> (a -> Builder) -> a -> SPut ()
fixedSized n f v = do
    appendBuilder $ f v
    addBuilderPosition n

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
expectedSized getLen f v = fixedSized (getLen v) f v

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

with16Length :: SPut () -> SPut ()
with16Length s = do
    pos <- builderPosition
    putInt16 0 -- fixed later
    beg <- builderPosition
    s
    end <- builderPosition
    let len = end - beg
    pushFixLen pos len
