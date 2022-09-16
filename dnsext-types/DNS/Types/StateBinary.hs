{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Types.StateBinary (
    PState(..)
  , initialState
  , SPut
  , runSPut
  , put8
  , put16
  , put32
  , putInt8
  , putInt16
  , putInt32
  , putShortByteString
  , putText
  , putReplicate
  , SGet
  , failSGet
  , fitSGet
  , runSGet
  , runSGetAt
  , runSGetWithLeftovers
  , runSGetWithLeftoversAt
  , get8
  , get16
  , get32
  , getInt8
  , getInt16
  , getInt32
  , getNShortByteString
  , getNText
  , sGetMany
  , getPosition
  , getInput
  , getAtTime
  , wsPop
  , wsPush
  , wsPosition
  , addPositionW
  , RawDomain
  , push
  , pop
  , getNBytes
  , getNOctets
  , skipNBytes
  , ST.gets
  ) where

import Control.Monad.State.Strict (State, StateT)
import qualified Control.Monad.State.Strict as ST
import qualified Data.Attoparsec.ByteString as A
import qualified Data.Attoparsec.Types as AT
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC8
import qualified Data.ByteString.Short as Short
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM
import Data.Map (Map)
import qualified Data.Map as M
import Data.Semigroup as Sem
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import DNS.Types.Error
import DNS.Types.Imports

----------------------------------------------------------------

type SPut = State WState Builder
type RawDomain = Text

data WState = WState {
    wsDomain :: Map RawDomain Int
  , wsPosition :: Int
}

initialWState :: WState
initialWState = WState M.empty 0

instance Sem.Semigroup SPut where
    p1 <> p2 = (Sem.<>) <$> p1 <*> p2

instance Monoid SPut where
    mempty = return mempty
#if !(MIN_VERSION_base(4,11,0))
    mappend = (Sem.<>)
#endif

put8 :: Word8 -> SPut
put8 = fixedSized 1 BB.word8

put16 :: Word16 -> SPut
put16 = fixedSized 2 BB.word16BE

put32 :: Word32 -> SPut
put32 = fixedSized 4 BB.word32BE

putInt8 :: Int -> SPut
putInt8 = fixedSized 1 (BB.int8 . fromIntegral)

putInt16 :: Int -> SPut
putInt16 = fixedSized 2 (BB.int16BE . fromIntegral)

putInt32 :: Int -> SPut
putInt32 = fixedSized 4 (BB.int32BE . fromIntegral)

putShortByteString :: ShortByteString -> SPut
putShortByteString = writeSized Short.length BB.shortByteString

putText :: Text -> SPut
putText = writeSized T.length T.encodeUtf8Builder

putReplicate :: Int -> Word8 -> SPut
putReplicate n w =
    fixedSized n BB.lazyByteString $ LB.replicate (fromIntegral n) w

addPositionW :: Int -> State WState ()
addPositionW n = do
    WState m cur <- ST.get
    ST.put $ WState m (cur+n)

fixedSized :: Int -> (a -> Builder) -> a -> SPut
fixedSized n f a = do addPositionW n
                      return (f a)

writeSized :: (a -> Int) -> (a -> Builder) -> a -> SPut
writeSized n f a = do addPositionW (n a)
                      return (f a)

wsPop :: RawDomain -> State WState (Maybe Int)
wsPop dom = do
    doms <- ST.gets wsDomain
    return $ M.lookup dom doms

wsPush :: RawDomain -> Int -> State WState ()
wsPush dom pos = do
    WState m cur <- ST.get
    ST.put $ WState (M.insert dom pos m) cur

----------------------------------------------------------------

type SGet = StateT PState (AT.Parser ByteString)

data PState = PState {
    psDomain :: IntMap RawDomain
  , psPosition :: Int
  , psInput :: ByteString
  , psAtTime  :: Int64
  }

----------------------------------------------------------------

getPosition :: SGet Int
getPosition = ST.gets psPosition

getInput :: SGet ByteString
getInput = ST.gets psInput

getAtTime :: SGet Int64
getAtTime = ST.gets psAtTime

addPosition :: Int -> SGet ()
addPosition n | n < 0 = failSGet "internal error: negative position increment"
              | otherwise = do
    PState dom pos inp t <- ST.get
    let pos' = pos + n
    when (pos' > BS.length inp) $
        failSGet "malformed or truncated input"
    ST.put $ PState dom pos' inp t

push :: Int -> RawDomain -> SGet ()
push n d = do
    PState dom pos inp t <- ST.get
    ST.put $ PState (IM.insert n d dom) pos inp t

pop :: Int -> SGet (Maybe RawDomain)
pop n = ST.gets (IM.lookup n . psDomain)

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

getNText :: Int -> SGet Text
getNText n | n < 0     = overrun
           | otherwise = ST.lift (T.decodeLatin1 <$> A.take n) <* addPosition n

fitSGet :: Int -> SGet a -> SGet a
fitSGet len parser | len < 0   = overrun
                   | otherwise = do
    pos0 <- getPosition
    ret <- parser
    pos' <- getPosition
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
            pos0 <- getPosition
            x    <- parser
            pos1 <- getPosition
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
dnsTimeMid :: Int64
dnsTimeMid = 3426660848

initialState :: Int64 -> ByteString -> PState
initialState t inp = PState IM.empty 0 inp t

-- Construct our own error message, without the unhelpful AttoParsec
-- \"Failed reading: \" prefix.
--
failSGet :: String -> SGet a
failSGet msg = ST.lift (fail "" A.<?> msg)

runSGetAt :: Int64 -> SGet a -> ByteString -> Either DNSError (a, PState)
runSGetAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t inp) inp
  where
    toResult :: A.Result r -> Either DNSError r
    toResult (A.Done _ r)        = Right r
    toResult (A.Fail _ ctx msg)  = Left $ DecodeError $ head $ ctx ++ [msg]
    toResult (A.Partial _)       = Left $ DecodeError "incomplete input"

runSGet :: SGet a -> ByteString -> Either DNSError (a, PState)
runSGet = runSGetAt dnsTimeMid

runSGetWithLeftoversAt :: Int64      -- ^ Reference time for DNS clock arithmetic
                       -> SGet a     -- ^ Parser
                       -> ByteString -- ^ Encoded message
                       -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftoversAt t parser inp =
    toResult $ A.parse (ST.runStateT parser $ initialState t inp) inp
  where
    toResult :: A.Result r -> Either DNSError (r, ByteString)
    toResult (A.Done     i r) = Right (r, i)
    toResult (A.Partial  f)   = toResult $ f BS.empty
    toResult (A.Fail _ ctx e) = Left $ DecodeError $ head $ ctx ++ [e]

runSGetWithLeftovers :: SGet a -> ByteString -> Either DNSError ((a, PState), ByteString)
runSGetWithLeftovers = runSGetWithLeftoversAt dnsTimeMid

runSPut :: SPut -> ByteString
runSPut = LC8.toStrict . BB.toLazyByteString . flip ST.evalState initialWState
