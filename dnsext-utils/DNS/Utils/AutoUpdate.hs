{-# LANGUAGE RecordWildCards #-}

module DNS.Utils.AutoUpdate (
    mkAutoUpdate,
    mkClosableAutoUpdate,
)
where

-- GHC packages
import GHC.Event (getSystemTimerManager, registerTimeout, unregisterTimeout)
import Control.Concurrent.STM
import Control.Monad
import Data.IORef

mkAutoUpdate :: Int -> IO a -> IO (IO a)
mkAutoUpdate micro uaction = fst <$> mkClosableAutoUpdate micro uaction

-- $setup
-- >>> :set -XNumericUnderscores
-- >>> import Control.Concurrent

-- |
-- >>> iref <- newIORef (0 :: Int)
-- >>> action = modifyIORef iref (+ 1) >> readIORef iref
-- >>> (getValue, closeState) <- mkClosableAutoUpdate 200_000 action
-- >>> getValue
-- 1
-- >>> threadDelay 100_000 >> getValue
-- 1
-- >>> threadDelay 200_000 >> getValue
-- 2
-- >>> closeState
mkClosableAutoUpdate :: Int -> IO a -> IO (IO a, IO ())
mkClosableAutoUpdate micro uaction = do
    us <- openUpdateState micro uaction
    pure (getUpdateResult us, closeUpdateState us)

--------------------------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data UpdateState a =
    UpdateState
    { usUpdateAction_   :: IO a
    , usLastResult_     :: IORef a
    , usIntervalMicro_  :: Int
    , usTimeHasCome_    :: TVar Bool
    , usDeleteTimeout_  :: IORef (IO ())
    }
{- FOURMOLU_ENABLE -}

mkDeleteTimeout :: TVar Bool -> Int -> IO (IO ())
mkDeleteTimeout thc micro =  do
    mgr <- getSystemTimerManager
    key <- registerTimeout mgr micro (atomically $ writeTVar thc True)
    pure $ unregisterTimeout mgr key

openUpdateState :: Int -> IO a -> IO (UpdateState a)
openUpdateState micro uaction = do
    thc <- newTVarIO False
    UpdateState uaction <$> (newIORef =<< uaction) <*> pure micro <*> pure thc <*> (newIORef =<< mkDeleteTimeout thc micro)

closeUpdateState :: UpdateState a -> IO ()
closeUpdateState UpdateState{..} = do
    delete <- readIORef usDeleteTimeout_
    delete

onceOnTimeHasCome :: UpdateState a -> IO () -> IO ()
onceOnTimeHasCome UpdateState{..} action = do
    action' <- atomically $ do
        timeHasCome <- readTVar usTimeHasCome_
        when timeHasCome $ writeTVar usTimeHasCome_ False
        pure $ when timeHasCome action
    action'

getUpdateResult :: UpdateState a -> IO a
getUpdateResult us@UpdateState{..} = do
    onceOnTimeHasCome us $ do
        writeIORef usLastResult_ =<< usUpdateAction_
        writeIORef usDeleteTimeout_ =<< mkDeleteTimeout usTimeHasCome_ usIntervalMicro_
    readIORef usLastResult_
