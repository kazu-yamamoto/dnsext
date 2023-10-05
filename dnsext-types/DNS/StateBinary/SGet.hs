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
import Control.Monad.IO.Class
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
newtype SGet a = SGet { runSGet' :: ReadBuffer -> IORef PState -> IO a }

instance Functor SGet where
    f `fmap` m = SGet $ \rbuf ref -> f `fmap` runSGet' m rbuf ref

instance Applicative SGet where
    pure x = SGet $ \_ _ -> pure x
    f <*> g = SGet $ \rbuf ref -> do
        f' <- runSGet' f rbuf ref
        g' <- runSGet' g rbuf ref
        pure $ f' g'

instance Monad SGet where
    m >>= f = SGet $ \rbuf ref -> do
        m' <- runSGet' m rbuf ref
        runSGet' (f m') rbuf ref

instance MonadIO SGet where
    liftIO m = SGet $ \_ _ -> m

-- | Parser state
data PState = PState
    { pstDomain :: IntMap [RawDomain]
    , pstAtTime :: EpochTime
    }
    deriving (Eq, Show)

initialState :: EpochTime -> PState
initialState t = PState IM.empty t

----------------------------------------------------------------

parserPosition :: SGet Position
parserPosition = SGet $ \rbuf _  -> position rbuf

getAtTime :: SGet EpochTime
getAtTime = SGet $ \_ ref -> pstAtTime <$> readIORef ref

pushDomain :: Position -> [RawDomain] -> SGet ()
pushDomain n d = SGet $ \_ ref -> do
    PState dom t <- readIORef ref
    writeIORef ref $ PState (IM.insert n d dom) t

popDomain :: Position -> SGet (Maybe [RawDomain])
popDomain n = SGet $ \_ ref -> IM.lookup n . pstDomain <$> readIORef ref

----------------------------------------------------------------

get8 :: SGet Word8
get8 = SGet (\rbuf _ -> read8 rbuf)

get16 :: SGet Word16
get16 = SGet (\rbuf _ -> read16 rbuf)

get32 :: SGet Word32
get32 = SGet (\rbuf _ -> read32 rbuf)

getInt8 :: SGet Int
getInt8 = fromIntegral <$> get8

getInt16 :: SGet Int
getInt16 = fromIntegral <$> get16

getInt32 :: SGet Int
getInt32 = fromIntegral <$> get32

----------------------------------------------------------------

getNBytes :: Int -> SGet [Int]
getNBytes n
    | n < 0 = error "malformed or truncated input"
    | otherwise = SGet $ \rbuf _ -> toInts <$> extractByteString rbuf n
  where
    toInts = map fromIntegral . BS.unpack

getNOctets :: Int -> SGet [Word8]
getNOctets n
    | n < 0 = error "malformed or truncated input"
    | otherwise = SGet $ \rbuf _ -> BS.unpack <$> extractByteString rbuf n

skipNBytes :: Int -> SGet ()
skipNBytes n
    | n < 0 = error "malformed or truncated input"
    | otherwise = SGet $ \rbuf _ -> ff rbuf n

getNByteString :: Int -> SGet ByteString
getNByteString n
    | n < 0 = error "malformed or truncated input"
    | otherwise = SGet $ \rbuf _ -> extractByteString rbuf n

getNShortByteString :: Int -> SGet ShortByteString
getNShortByteString n
    | n < 0 = error "malformed or truncated input"
    | otherwise = SGet $ \rbuf _ -> Short.toShort <$> extractByteString rbuf n

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
sGetMany elemname len parser = SGet $ \rbuf ref -> do
    lim <- (+ len) <$> position rbuf
    go lim id rbuf ref
  where
    go lim build rbuf ref = do
        pos <- position rbuf
        case pos `compare` lim of
          EQ -> return $ build []
          LT -> do
              x <- runSGet' parser rbuf ref
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

failSGet :: String -> SGet a
failSGet = error

runSGetAt :: EpochTime -> SGet a -> ByteString -> Either DNSError a
runSGetAt t parser inp =
    unsafeDupablePerformIO $ E.handle handler parse
  where
    parse = withReadBuffer inp $ \rbuf -> do
        ref <- newIORef $ initialState t
        Right <$> runSGet' parser rbuf ref
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
