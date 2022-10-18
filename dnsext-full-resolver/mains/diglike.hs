
import System.Environment (getArgs)

import DigLike.CommandArgs (parseParams, Params, help)
import DigLike.Operation (operate)
import DigLike.Output (pprResult)

parseArgs :: [String] -> IO Params
parseArgs args = either fail (return . fst) $ parseParams args

main :: IO ()
main = do
  args <- getArgs
  case take 1 args of
    [x] | x `elem` ["-h", "--help"]  -> putStr $ help
    _                                ->
      either (fail . show) (putStr . pprResult args)
      =<< uncurry (uncurry $ uncurry operate) =<< parseArgs args
