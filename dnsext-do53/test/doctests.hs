{-# LANGUAGE CPP #-}

-- | Run doctests only on non-Windows systems with GHC 8.4 or later.
--
-- The Windows doctests now compile and run, but either succeed quickly or
-- randomly hang (before AppVeyor kills them after an hour).  So we disable
-- these for now.  This can be tested again at some point in the future.
--
module Main where

#if !defined(mingw32_HOST_OS) && MIN_TOOL_VERSION_ghc(8,4,0)
import Test.DocTest
import System.Environment

-- | Expose precompiled library modules.
modules :: [String]
modules =
  [ "-XOverloadedStrings"
  , "-XCPP"
  , "-XLambdaCase"
  , "-XPatternSynonyms"
  , "-i","-i."
  , "-threaded"
  , "DNS/IO.hs"
  , "DNS/IO/Utils.hs"
  ]

main :: IO ()
main = getArgs >>= doctest . (++ modules)

#else

main :: IO ()
main = return ()

#endif
