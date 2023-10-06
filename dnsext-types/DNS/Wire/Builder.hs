{-# LANGUAGE FlexibleInstances #-}

module DNS.Wire.Builder (
    -- * Builder
    Builder,
    WriteBuffer,
    runBuilder,

    -- ** Basic builders
    put8,
    put16,
    put32,
    putInt8,
    putInt16,
    putInt32,
    putShortByteString,
    putLenShortByteString,

    -- ** Lower utilities
    with16Length,

    -- ** Builder state
    BState,
    builderPosition,
    pushPointer,
    popPointer,
) where

import qualified Data.ByteString.Short as Short
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as M
import Network.ByteOrder
import System.IO.Unsafe (unsafeDupablePerformIO)

import DNS.Wire.Types
import DNS.Types.Imports

----------------------------------------------------------------

-- | Builder type
type Builder a = WriteBuffer -> IORef BState -> IO a

----------------------------------------------------------------

-- | Builder state
newtype BState = BState
    { bstDomain :: Map [RawDomain] Int
    }

initialBState :: BState
initialBState = BState M.empty

----------------------------------------------------------------

runBuilder :: Builder () -> ByteString
runBuilder builder = unsafeDupablePerformIO $ do
    withWriteBuffer 2048 $ \wbuf -> do -- fixme
        ref <- newIORef initialBState
        builder wbuf ref

----------------------------------------------------------------

builderPosition :: WriteBuffer -> IO Position
builderPosition = position

popPointer :: [RawDomain] -> IORef BState -> IO (Maybe Int)
popPointer dom ref = M.lookup dom . bstDomain <$> readIORef ref

pushPointer :: [RawDomain] -> Int -> IORef BState -> IO ()
pushPointer dom pos ref = do
    BState m <- readIORef ref
    let m' = M.insert dom pos m
    writeIORef ref $ BState m'

----------------------------------------------------------------

put8 :: WriteBuffer -> Word8 -> IO ()
put8 = write8

put16 :: WriteBuffer -> Word16 -> IO ()
put16 = write16

put32 :: WriteBuffer -> Word32 -> IO ()
put32 = write32

putInt8 :: WriteBuffer -> Int -> IO ()
putInt8 wbuf n = write8 wbuf $ fromIntegral n

putInt16 :: WriteBuffer -> Int -> IO ()
putInt16 wbuf n = write16 wbuf $ fromIntegral n

putInt32 :: WriteBuffer -> Int -> IO ()
putInt32 wbuf n = write32 wbuf $ fromIntegral n

----------------------------------------------------------------

putShortByteString :: WriteBuffer -> ShortByteString -> IO ()
putShortByteString = copyShortByteString

-- In the case of the TXT record, we need to put the string length
putLenShortByteString :: WriteBuffer -> ShortByteString -> IO ()
putLenShortByteString wbuf txt = do
    write8 wbuf len
    putShortByteString wbuf txt
  where
    len = fromIntegral $ Short.length txt

with16Length :: Builder () -> Builder ()
with16Length builder wbuf ref = do
    save wbuf
    write16 wbuf 0 -- reserve space
    beg <- position wbuf
    builder wbuf ref
    end <- position wbuf
    let len = end - beg
    goBack wbuf
    write16 wbuf $ fromIntegral len
    ff wbuf len
