module DNS.Iterative.Query.Random (
    randomizedSelect,
    randomizedSelectN,
    randomizedChoice,
    randomizedSelects,
    randomizedPerm,
    randomizedPermN,
) where

-- GHC packages
import Data.Array.IO hiding (range)
import System.IO.Unsafe (unsafeInterleaveIO)

-- other packages
import System.Random (getStdRandom, randomR)

-- dnsext packages

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

{- FOURMOLU_DISABLE -}
randomizedChoice :: MonadIO m => a -> a -> m a
randomizedChoice x y
    | randomSelect = bool x y <$> getStdRandom (randomR (False, True))
    | otherwise    = pure x
{- FOURMOLU_ENABLE -}

randomizedSelects :: MonadIO m => Int -> [a] -> m [a]
randomizedSelects num xs
    | len <= num = return xs
    | otherwise = do
        ix <- randomizedIndex (0, len - 1)
        return $ take num $ drop ix $ xs ++ xs
  where
    len = length xs

-- $setup
-- >>> :seti -Wno-incomplete-patterns
-- >>> import Data.List

{- FOURMOLU_DISABLE -}
-- |
-- >>> toList' (x:|xs) = x : xs
-- >>> nonEmpty' (x:xs) = x :| xs
-- >>> permCheck xs = (\rs -> sort (toList' rs) == sort xs) <$> randomizedPermN (nonEmpty' xs)
-- >>> permCheck ['x']
-- True
-- >>> permCheck ['q','p','r']
-- True
-- >>> permCheck ['p'..'z']
-- True
randomizedPermN :: MonadIO m => NonEmpty a -> m (NonEmpty a)
randomizedPermN (x :| xs) = liftIO $ unsafeInterleaveIO $ do
    let nsz = length xs
    ss <- newListArray (0, nsz) (x:xs)
    v1 <- permStep nsz ss
    (v1 :|) <$> interleavedPerm nsz ss
{- FOURMOLU_ENABLE -}

randomizedPerm :: MonadIO m => [a] -> m [a]
randomizedPerm xs = do
    let tsz = length xs
    liftIO $ interleavedPerm tsz =<< newListArray (0, tsz - 1) xs

{- FOURMOLU_DISABLE -}
interleavedPerm :: Int -> IOArray Int a -> IO [a]
interleavedPerm tsz ss = go tsz
  where
    go 0  = pure []
    go sz = unsafeInterleaveIO $ do
        let nsz = sz - 1
        (:) <$> permStep nsz ss <*> go nsz
{- FOURMOLU_ENABLE -}

permStep :: Int -> IOArray Int a -> IO a
permStep nsz ss = do
    ix <- randomizedIndex (0, nsz)
    v <- readArray ss ix
    when (ix /= nsz) $ writeArray ss ix =<< readArray ss nsz
    pure v
