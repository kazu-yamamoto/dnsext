{-# LANGUAGE CPP #-}

import Test.DocTest
import System.Environment

-- | Expose precompiled library modules.
modules :: [String]
modules =
  [ "-XOverloadedStrings"
#if MIN_TOOL_VERSION_ghc(8,0,0)
  , "-XStrict"
  , "-XStrictData"
#endif
  , "DNS/SEC.hs"
  ]

main :: IO ()
main = getArgs >>= doctest . (++ modules)
