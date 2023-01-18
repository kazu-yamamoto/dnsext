{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.StateBinary.SGet (
  -- * Parser
    SGet
  , failSGet
  , fitSGet
  , runSGet
  , runSGetAt
  , runSGetWithLeftovers
  , runSGetWithLeftoversAt
  , runSGetChunks
  -- ** Basic parsers
  , get8
  , get16
  , get32
  , getInt8
  , getInt16
  , getInt32
  , getNByteString
  , getNShortByteString
  , sGetMany
  , getNBytes
  , getNOctets
  , skipNBytes
  -- ** Parser state
  , PState
  , parserPosition
  , pushDomain
  , popDomain
  , getAtTime
  ) where

import Control.Monad.State.Strict (StateT)
import qualified Control.Monad.State.Strict as ST
import qualified Data.Attoparsec.ByteString as A
import qualified Data.Attoparsec.Types as AT
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM

import DNS.StateBinary.Types
import DNS.Types.Error
import DNS.Types.Imports

----------------------------------------------------------------

-- | Parser type
type SGet = StateT PState (AT.Parser ByteString)

-- | Parser state
data PState = PState {
    pstDomain   :: IntMap [RawDomain]
  , pstPosition :: Position
  , pstAtTime   :: EpochTime
  }

initialState :: EpochTime -> PState
initialState t = PState IM.empty 0 t

----------------------------------------------------------------

parserPosition :: SGet Position
parserPosition = ST.gets pstPosition

getAtTime :: SGet EpochTime
getAtTime = ST.gets pstAtTime

addPosition :: Position -> SGet ()
addPosition n | n < 0 = failSGet "internal error: negative position increment"
              | otherwise = do
    PState dom pos t <- ST.get
    let pos' = pos + n
    ST.put $ PState dom pos' t

pushDomain :: Position -> [RawDomain] -> SGet ()
pushDomain n d = do
    PState dom pos t <- ST.get
    ST.put $ PState (IM.insert n d dom) pos t

popDomain :: Position -> SGet (Maybe [RawDomain])
popDomain n = ST.gets (IM.lookup n . pstDomain)

----------------------------------------------------------------

get8 :: SGet Word8
get8  = ST.lift A.anyWord8 <* addPosition 1

get16 :: SGet Word16
get16 = ST.lift getWord16be <* addPosition 2
  where
    word8' = fromIntegral <$> A.anyWord8
    getWord16be = do
        a <- word8'
        b <- word8'
        return $ a * 0x100 + b

get32 :: SGet Word32
get32 = ST.lift getWord32be <* addPosition 4
  where
    word8' = fromIntegral <$> A.anyWord8
    getWord32be = do
        a <- word8'
        b <- word8'
        c <- word8'
        d <- word8'
        return $ a * 0x1000000 + b * 0x10000 + c * 0x100 + d

getInt8 :: SGet Int
getInt8 = fromIntegral <$> get8

getInt16 :: SGet Int
getInt16 = fromIntegral <$> get16

getInt32 :: SGet Int
getInt32 = fromIntegral <$> get32

----------------------------------------------------------------

overrun :: SGet a
overrun = failSGet "malformed or truncated input"

getNBytes :: Int -> SGet [Int]
getNBytes n | n < 0     = overrun
            | otherwise = toInts <$> getNByteString n
  where
    toInts = map fromIntegral . BS.unpack

getNOctets :: Int -> SGet [Word8]
getNOctets n | n < 0     = overrun
             | otherwise = BS.unpack <$> getNByteString n

skipNBytes :: Int -> SGet ()
skipNBytes n | n < 0     = overrun
             | otherwise = ST.lift (A.take n) >> addPosition n

getNByteString :: Int -> SGet ByteString
getNByteString n | n < 0     = overrun
                 | otherwise = ST.lift (A.take n) <* addPosition n

getNShortByteString :: Int -> SGet ShortByteString
getNShortByteString n | n < 0     = overrun
                      | otherwise = ST.lift (Short.toShort <$> A.take n) <* addPosition n

fitSGet :: Int -> SGet a -> SGet a
fitSGet len parser | len < 0   = overrun
                   | otherwise = do
    pos0 <- parserPosition
    ret <- parser
    pos' <- parserPosition
    if pos' == pos0 + len
    then return ret
    else if pos' > pos0 + len
    then failSGet "element size exceeds declared size"
    else failSGet "element shorter than declared size"

-- | Parse a list of elements that takes up exactly a given number of bytes.
-- In order to avoid infinite loops, if an element parser succeeds without
-- moving the buffer offset forward, an error will be returned.
--
sGetMany :: String -- ^ element type for error messages
         -> Int    -- ^ input buffer length
         -> SGet a -- ^ element parser
         -> SGet [a]
sGetMany elemname len parser | len < 0   = overrun
                             | otherwise = go len []
  where
    go n xs
        | n < 0     = failSGet $ elemname ++ " longer than declared size"
        | n == 0    = pure $ reverse xs
        | otherwise = do
            pos0 <- parserPosition
            x    <- parser
            pos1 <- parserPosition
            if pos1 <= pos0
            then failSGet $ "internal error: in-place success for " ++ elemname
            else go (n + pos0 - pos1) (x : xs)

----------------------------------------------------------------

-- | To get a broad range of correct RRSIG inception and expiration times
-- without over or underflow, we choose a time half way between midnight PDT
-- 2010-07-15 (the day the root zone was signed) and 2^32 seconds later on
-- 2146-08-21.  Since 'decode' and 'runSGet' are pure, we can't peek at the
-- current time while parsing.  Outside this date range the output is off by
-- some non-zero multiple 2\^32 seconds.
--
dnsTimeMid :: EpochTime
dnsTimeMid = 3426660848

-- Construct our own error message, without the unhelpful AttoParsec
-- \"Failed reading: \" prefix.
--
failSGet :: String -> SGet a
failSGet msg = ST.lift (fail "" A.<?> msg)

runSGetAt :: EpochTime -> SGet a -> ByteString -> Either DNSError (a, PState)
runSGetAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t) inp
  where
    toResult :: A.Result r -> Either DNSError r
    toResult (A.Done _ r)        = Right r
    toResult (A.Fail _ ctx msg)  = Left $ DecodeError $ head $ ctx ++ [msg]
    toResult (A.Partial _)       = Left $ DecodeError "incomplete input"

runSGet :: SGet a -> ByteString -> Either DNSError (a, PState)
runSGet = runSGetAt dnsTimeMid

runSGetWithLeftoversAt :: EpochTime  -- ^ Reference time for DNS clock arithmetic
                       -> SGet a     -- ^ Parser
                       -> ByteString -- ^ Encoded message
                       -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftoversAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t) inp
  where
    toResult :: A.Result r -> Either DNSError (r, ByteString)
    toResult (A.Done     i r) = Right (r, i)
    toResult (A.Partial  f)   = toResult $ f BS.empty
    toResult (A.Fail _ ctx e) = Left $ DecodeError $ head $ ctx ++ [e]

runSGetWithLeftovers :: SGet a -> ByteString -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftovers = runSGetWithLeftoversAt dnsTimeMid

----------------------------------------------------------------

runSGetChunks :: EpochTime  -- ^ Reference time for DNS clock arithmetic
              -> SGet a     -- ^ Parser
              -> [ByteString] -- ^ Encoded message
              -> Either DNSError ((a, PState), [ByteString])
runSGetChunks t parser inps0 = go cont0 inps0
    where
    st0 = initialState t
    cont0 = A.parse (ST.runStateT parser st0)
    go _ []         = Left $ DecodeError "not enough data"
    go cont (inp:inps) = case cont inp of
      A.Done     i r  -> Right (r, if i == "" then inps else i:inps)
      A.Partial cont' -> go cont' inps
      A.Fail _ ctx e  -> Left $ DecodeError $ head $ ctx ++ [e]
