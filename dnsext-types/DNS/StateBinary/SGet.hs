{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.StateBinary.SGet (
    -- * Parser
    SGet,
    failSGet,
    runSGet,
    runSGetAt,

    -- ** Basic parsers
    get8,
    get16,
    get32,
    getInt8,
    getInt16,
    getInt32,
    getNByteString,
    getNShortByteString,
    sGetMany,
    getNBytes,
    getNOctets,
    skipNBytes,

    -- ** Parser state
    PState,
    parserPosition,
    pushDomain,
    popDomain,
    getAtTime,
) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Data.IORef
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM
import Network.ByteOrder
import System.IO.Unsafe (unsafeDupablePerformIO)

import DNS.StateBinary.Types
import DNS.Types.Error
import DNS.Types.Imports
import DNS.Types.Time

----------------------------------------------------------------

-- | Parser type
type SGet a = ReadBuffer -> IORef PState -> IO a

-- | Parser state
data PState = PState
    { pstDomain :: IntMap [RawDomain]
    , pstAtTime :: EpochTime
    }
    deriving (Eq, Show)

initialState :: EpochTime -> PState
initialState t = PState IM.empty t

----------------------------------------------------------------

parserPosition :: ReadBuffer -> IO Int
parserPosition = position

getAtTime :: IORef PState -> IO EpochTime
getAtTime ref = pstAtTime <$> readIORef ref

pushDomain :: IM.Key -> [RawDomain] -> IORef PState -> IO ()
pushDomain n d ref = do
    PState dom t <- readIORef ref
    writeIORef ref $ PState (IM.insert n d dom) t

popDomain :: IM.Key -> IORef PState -> IO (Maybe [RawDomain])
popDomain n ref = IM.lookup n . pstDomain <$> readIORef ref

----------------------------------------------------------------

get8 :: ReadBuffer -> IO Word8
get8 = read8

get16 :: ReadBuffer -> IO Word16
get16 = read16

get32 :: ReadBuffer -> IO Word32
get32 = read32

getInt8 :: ReadBuffer -> IO Int
getInt8 rbuf = fromIntegral <$> get8 rbuf

getInt16 :: ReadBuffer -> IO Int
getInt16 rbuf = fromIntegral <$> get16 rbuf

getInt32 :: ReadBuffer -> IO Int
getInt32 rbuf = fromIntegral <$> get32 rbuf

----------------------------------------------------------------

getNBytes :: ReadBuffer -> Int -> IO [Int]
getNBytes rbuf n
    | n < 0 = error "malformed or truncated input"
    | otherwise = toInts <$> extractByteString rbuf n
  where
    toInts = map fromIntegral . BS.unpack

getNOctets :: ReadBuffer -> Int -> IO [Word8]
getNOctets rbuf n
    | n < 0 = error "malformed or truncated input"
    | otherwise = BS.unpack <$> extractByteString rbuf n

skipNBytes :: ReadBuffer -> Int -> IO ()
skipNBytes rbuf n
    | n < 0 = error "malformed or truncated input"
    | otherwise = ff rbuf n

getNByteString :: ReadBuffer -> Int -> IO ByteString
getNByteString rbuf n
    | n < 0 = error "malformed or truncated input"
    | otherwise = extractByteString rbuf n

getNShortByteString :: ReadBuffer -> Int -> IO ShortByteString
getNShortByteString rbuf n
    | n < 0 = error "malformed or truncated input"
    | otherwise = Short.toShort <$> extractByteString rbuf n

-- | Parse a list of elements that takes up exactly a given number of bytes.
-- In order to avoid infinite loops, if an element parser succeeds without
-- moving the buffer offset forward, an error will be returned.
sGetMany
    :: String
    -- ^ element type for error messages
    -> Int
    -- ^ input buffer length
    -> SGet a
    -- ^ element parser
    -> SGet [a]
sGetMany elemname len parser = \rbuf ref -> do
    lim <- (+ len) <$> position rbuf
    go lim id rbuf ref
  where
    go lim build rbuf ref = do
        pos <- position rbuf
        case pos `compare` lim of
          EQ -> return $ build []
          LT -> do
              x <- parser rbuf ref
              go lim (build . (x :)) rbuf ref
          GT -> error $ "internal error: in-place success for " ++ elemname

----------------------------------------------------------------

-- | To get a broad range of correct RRSIG inception and expiration times
-- without over or underflow, we choose a time half way between midnight PDT
-- 2010-07-15 (the day the root zone was signed) and 2^32 seconds later on
-- 2146-08-21.  Since 'decode' and 'runSGet' are pure, we can't peek at the
-- current time while parsing.  Outside this date range the output is off by
-- some non-zero multiple 2\^32 seconds.
dnsTimeMid :: EpochTime
dnsTimeMid = 3426660848

failSGet :: Monad m => String -> m a
failSGet = error

runSGetAt :: EpochTime -> SGet a -> ByteString -> Either DNSError a
runSGetAt t parser inp =
    unsafeDupablePerformIO $ E.handle handler parse
  where
    parse = withReadBuffer inp $ \rbuf -> do
        ref <- newIORef $ initialState t
        Right <$> parser rbuf ref
    handler (E.SomeException e) = return $ Left $ DecodeError $ "incomplete input: " ++ show e

runSGet :: SGet a -> ByteString -> Either DNSError a
runSGet = runSGetAt dnsTimeMid

{-
runSGetWithLeftoversAt
    :: EpochTime
    -- ^ Reference time for DNS clock arithmetic
    -> SGet a
    -- ^ Parser
    -> ByteString
    -- ^ Encoded message
    -> Either DNSError a
runSGetWithLeftoversAt t parser inp =
    unsafeDupablePerformIO $ E.handle handler parse
  where
    parse = withReadBuffer inp $ \rbuf -> do
        ref <- newIORef $ initialState t
        Right <$> runSGet' parser rbuf ref
    handler (E.SomeException e) = return $ Left $ DecodeError ("incomplete input: " ++ show e)

runSGetWithLeftovers
    :: SGet a -> ByteString -> Either DNSError a
runSGetWithLeftovers = runSGetWithLeftoversAt dnsTimeMid
-}
