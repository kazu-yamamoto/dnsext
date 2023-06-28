module DNS.Cache.Iterative.Random (
    randomizedSelect,
    randomizedSelectN,
    selectIPs,
) where

-- GHC packages
import Control.Monad.IO.Class (MonadIO)
import Data.Maybe (listToMaybe)

-- other packages

import System.Random (getStdRandom, randomR)

-- dns packages

import Data.IP (IP)

-- this package
import DNS.Cache.Types (NE)

randomSelect :: Bool
randomSelect = True

randomizedIndex :: MonadIO m => (Int, Int) -> m Int
randomizedIndex range
    | randomSelect = getStdRandom $ randomR range
    | otherwise = return 0

randomizedSelectN :: MonadIO m => NE a -> m a
randomizedSelectN
    | randomSelect = d
    | otherwise = return . fst -- naive implementation
  where
    d (x, []) = return x
    d (x, xs@(_ : _)) = do
        let xxs = x : xs
        ix <- randomizedIndex (0, length xxs - 1)
        return $ xxs !! ix

randomizedSelect :: MonadIO m => [a] -> m (Maybe a)
randomizedSelect
    | randomSelect = d
    | otherwise = return . listToMaybe -- naive implementation
  where
    d [] = return Nothing
    d [x] = return $ Just x
    d xs@(_ : _ : _) = do
        ix <- randomizedIndex (0, length xs - 1)
        return $ Just $ xs !! ix

selectIPs :: MonadIO m => Int -> [IP] -> m [IP]
selectIPs num ips
    | len <= num = return ips
    | otherwise = do
        ix <- randomizedIndex (0, len - 1)
        return $ take num $ drop ix $ ips ++ ips
  where
    len = length ips