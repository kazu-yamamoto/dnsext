{-# LANGUAGE DeriveFunctor #-}

module DNS.Types.Dict (
    getRData,
    getOData,
    extendRR,
    extendOpt,
    InitIO,
    runInitIO,
) where

import Control.Monad.IO.Class (MonadIO (..))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.IntMap as M
import System.IO.Unsafe (unsafePerformIO)

import DNS.Types.EDNS
import DNS.Types.Opaque.Internal
import DNS.Types.RData
import DNS.Types.Type
import DNS.Wire

----------------------------------------------------------------

{-# NOINLINE globalRDataDict #-}
globalRDataDict :: IORef RDataDict
globalRDataDict = unsafePerformIO $ newIORef defaultRDataDict

{-# NOINLINE globalODataDict #-}
globalODataDict :: IORef ODataDict
globalODataDict = unsafePerformIO $ newIORef defaultODataDict

addRData :: TYPE -> (Int -> Parser RData) -> IO ()
addRData typ dec = atomicModifyIORef' globalRDataDict f
  where
    f dict = (M.insert (toKey typ) dec dict, ())

addOData :: OptCode -> (Int -> Parser OData) -> IO ()
addOData code dec = atomicModifyIORef' globalODataDict f
  where
    f dict = (M.insert (toKeyO code) dec dict, ())

----------------------------------------------------------------

getRData :: TYPE -> Int -> Parser RData
getRData OPT len rbuf ref = rd_opt <$> sGetMany "EDNS option" len getoption rbuf ref
  where
    dict = unsafePerformIO $ readIORef globalODataDict
    getoption _ _ = do
        code <- toOptCode <$> get16 rbuf
        olen <- getInt16 rbuf
        getOData dict code olen rbuf ref
getRData typ len rbuf ref = case M.lookup (toKey typ) dict of
    Nothing -> rd_unknown typ <$> getOpaque len rbuf ref
    Just dec -> dec len rbuf ref
  where
    dict = unsafePerformIO $ readIORef globalRDataDict

----------------------------------------------------------------

type RDataDict = M.IntMap (Int -> Parser RData)

toKey :: TYPE -> M.Key
toKey = fromIntegral . fromTYPE

defaultRDataDict :: M.IntMap (Int -> Parser RData)
defaultRDataDict =
    M.insert (toKey A) (\len rbuf ref -> toRData <$> get_a len rbuf ref) $
        M.insert (toKey NS) (\len rbuf ref -> toRData <$> get_ns len rbuf ref) $
            M.insert (toKey CNAME) (\len rbuf ref -> toRData <$> get_cname len rbuf ref) $
                M.insert (toKey SOA) (\len rbuf ref -> toRData <$> get_soa len rbuf ref) $
                    M.insert (toKey NULL) (\len rbuf ref -> toRData <$> get_null len rbuf ref) $
                        M.insert (toKey PTR) (\len rbuf ref -> toRData <$> get_ptr len rbuf ref) $
                            M.insert (toKey MX) (\len rbuf ref -> toRData <$> get_mx len rbuf ref) $
                                M.insert (toKey TXT) (\len rbuf ref -> toRData <$> get_txt len rbuf ref) $
                                    M.insert (toKey RP) (\len rbuf ref -> toRData <$> get_rp len rbuf ref) $
                                        M.insert (toKey AAAA) (\len rbuf ref -> toRData <$> get_aaaa len rbuf ref) $
                                            M.insert (toKey SRV) (\len rbuf ref -> toRData <$> get_srv len rbuf ref) $
                                                M.insert (toKey DNAME) (\len rbuf ref -> toRData <$> get_dname len rbuf ref) $
                                                    M.insert
                                                        (toKey TLSA)
                                                        (\len rbuf ref -> toRData <$> get_tlsa len rbuf ref)
                                                        M.empty

----------------------------------------------------------------

type ODataDict = M.IntMap (Int -> Parser OData)

getOData :: ODataDict -> OptCode -> Int -> Parser OData
getOData dict code len rbuf ref = case M.lookup (toKeyO code) dict of
    Nothing -> od_unknown (fromOptCode code) <$> getOpaque len rbuf ref
    Just dec -> dec len rbuf ref

toKeyO :: OptCode -> M.Key
toKeyO = fromIntegral . fromOptCode

defaultODataDict :: ODataDict
defaultODataDict =
    M.insert (toKeyO NSID) (\len rbuf ref -> toOData <$> get_nsid len rbuf ref) $
        M.insert (toKeyO ClientSubnet) (\len rbuf ref -> toOData <$> get_clientSubnet len rbuf ref) $
            M.insert (toKeyO Padding) (\len rbuf ref -> toOData <$> get_padding len rbuf ref) $
                M.insert (toKeyO EDNSError) (\len rbuf ref -> toOData <$> get_ednsError len rbuf ref) $
                    M.empty

----------------------------------------------------------------

extendRR :: TYPE -> String -> (Int -> Parser RData) -> InitIO ()
extendRR typ name proxy = InitIO $ do
    addRData typ proxy
    addType typ name

extendOpt :: OptCode -> String -> (Int -> Parser OData) -> InitIO ()
extendOpt code name proxy = InitIO $ do
    addOData code proxy
    addOpt code name

----------------------------------------------------------------

newtype InitIO a = InitIO
    { runInitIO :: IO a
    }
    deriving (Functor)

instance Applicative InitIO where
    pure x = InitIO $ pure x
    InitIO x <*> InitIO y = InitIO (x <*> y)

instance Monad InitIO where
    m >>= f = InitIO $ do
        x <- runInitIO m
        runInitIO $ f x

instance MonadIO InitIO where
    liftIO = InitIO
