import Test.DocTest
import System.Environment

-- | Expose precompiled library modules.
modules :: [String]
modules =
  [ "-XOverloadedStrings"
  , "DNS/SEC.hs"
  ]

main :: IO ()
main = getArgs >>= doctest . (++ modules)
