{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.StateBinary.SPut (
    SPut
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
  , WState
  , wsPop
  , wsPush
  , wsPosition
  , addPositionW
  , State
  , ST.modify
  , ST.execState
  ) where

import Control.Monad.State.Strict (State)
import qualified Control.Monad.State.Strict as ST
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC8
import qualified Data.ByteString.Short as Short
import Data.Map (Map)
import qualified Data.Map as M
import Data.Semigroup as Sem
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import DNS.StateBinary.Types
import DNS.Types.Imports

----------------------------------------------------------------

type SPut = State WState Builder

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

runSPut :: SPut -> ByteString
runSPut = LC8.toStrict . BB.toLazyByteString . flip ST.evalState initialWState
