{-# LANGUAGE DeriveFunctor #-}

module DNS.Types.Dict (
    getRData
  , getOData
  , extendRR
  , extendOpt
  , InitIO
  , runInitIO
  ) where

import Control.Monad.IO.Class (MonadIO(..))
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import qualified Data.IntMap as M
import System.IO.Unsafe (unsafePerformIO)

import DNS.StateBinary
import DNS.Types.EDNS
import DNS.Types.Opaque.Internal
import DNS.Types.RData
import DNS.Types.Type

----------------------------------------------------------------

{-# NOINLINE globalRDataDict #-}
globalRDataDict :: IORef RDataDict
globalRDataDict = unsafePerformIO $ newIORef defaultRDataDict

{-# NOINLINE globalODataDict #-}
globalODataDict :: IORef ODataDict
globalODataDict = unsafePerformIO $ newIORef defaultODataDict

addRData :: TYPE -> (Int -> SGet RData) -> IO ()
addRData typ dec = atomicModifyIORef' globalRDataDict f
  where
    f dict = (M.insert (toKey typ) dec dict, ())

addOData :: OptCode -> (Int -> SGet OData) -> IO ()
addOData code dec = atomicModifyIORef' globalODataDict f
  where
    f dict = (M.insert (toKeyO code) dec dict, ())

----------------------------------------------------------------

getRData :: TYPE -> Int -> SGet RData
getRData OPT len = rd_opt <$> sGetMany "EDNS option" len getoption
  where
    dict = unsafePerformIO $ readIORef globalODataDict
    getoption = do
        code <- toOptCode <$> get16
        olen <- getInt16
        getOData dict code olen
getRData typ len = case M.lookup (toKey typ) dict of
    Nothing  -> rd_unknown typ <$> getOpaque len
    Just dec -> dec len
  where
    dict = unsafePerformIO $ readIORef globalRDataDict

----------------------------------------------------------------

type RDataDict = M.IntMap (Int -> SGet RData)

toKey :: TYPE -> M.Key
toKey = fromIntegral . fromTYPE

defaultRDataDict :: M.IntMap (Int -> SGet RData)
defaultRDataDict =
    M.insert (toKey A)     (\len -> toRData <$> getRD_A     len)
  $ M.insert (toKey NS)    (\len -> toRData <$> getRD_NS    len)
  $ M.insert (toKey CNAME) (\len -> toRData <$> getRD_CNAME len)
  $ M.insert (toKey SOA)   (\len -> toRData <$> getRD_SOA   len)
  $ M.insert (toKey NULL)  (\len -> toRData <$> getRD_NULL  len)
  $ M.insert (toKey PTR)   (\len -> toRData <$> getRD_PTR   len)
  $ M.insert (toKey MX)    (\len -> toRData <$> getRD_MX    len)
  $ M.insert (toKey TXT)   (\len -> toRData <$> getRD_TXT   len)
  $ M.insert (toKey RP)    (\len -> toRData <$> getRD_RP    len)
  $ M.insert (toKey AAAA)  (\len -> toRData <$> getRD_AAAA  len)
  $ M.insert (toKey SRV)   (\len -> toRData <$> getRD_SRV   len)
  $ M.insert (toKey DNAME) (\len -> toRData <$> getRD_DNAME len)
  $ M.insert (toKey TLSA)  (\len -> toRData <$> getRD_TLSA  len)
    M.empty

----------------------------------------------------------------

type ODataDict = M.IntMap (Int -> SGet OData)

getOData :: ODataDict -> OptCode -> Int -> SGet OData
getOData dict code len = case M.lookup (toKeyO code) dict of
    Nothing  -> od_unknown (fromOptCode code) <$> getOpaque len
    Just dec -> dec len

toKeyO :: OptCode -> M.Key
toKeyO = fromIntegral . fromOptCode

defaultODataDict :: ODataDict
defaultODataDict =
    M.insert (toKeyO NSID)         (\len -> toOData <$> decodeOD_NSID len)
  $ M.insert (toKeyO ClientSubnet) (\len -> toOData <$> decodeOD_ClientSubnet len)
  $ M.insert (toKeyO Padding)      (\len -> toOData <$> decodeOD_Padding len)
    M.empty

----------------------------------------------------------------

extendRR :: TYPE -> String -> (Int -> SGet RData) -> InitIO ()
extendRR typ name proxy = InitIO $ do
    addRData typ proxy
    addType typ name

extendOpt :: OptCode -> String -> (Int -> SGet OData) -> InitIO ()
extendOpt code name proxy = InitIO $ do
    addOData code proxy
    addOpt code name

----------------------------------------------------------------

newtype InitIO a = InitIO {
    runInitIO :: IO a
  } deriving (Functor)

instance Applicative InitIO where
    pure x                = InitIO $ pure x
    InitIO x <*> InitIO y = InitIO (x <*> y)

instance Monad InitIO where
    m >>= f = InitIO $ do
        x <- runInitIO m
        runInitIO $ f x

instance MonadIO InitIO where
    liftIO = InitIO
