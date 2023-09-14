module DNS.Iterative.Query.Random (
    randomizedSelect,
    randomizedSelectN,
    selectIPs,
) where

-- GHC packages

-- other packages
import System.Random (getStdRandom, randomR)

-- dnsext packages
import Data.List.NonEmpty (NonEmpty(..))
import Data.IP (IP)

-- this package
import DNS.Iterative.Imports

randomSelect :: Bool
randomSelect = True

randomizedIndex :: MonadIO m => (Int, Int) -> m Int
randomizedIndex range
    | randomSelect = getStdRandom $ randomR range
    | otherwise = return 0

randomizedSelectN :: MonadIO m => NonEmpty a -> m a
randomizedSelectN
    | randomSelect = d
    | otherwise = d' -- naive implementation
  where
    d' (x :| _) = return x
    d (x :| []) = return x
    d (x :| xs@(_ : _)) = do
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
