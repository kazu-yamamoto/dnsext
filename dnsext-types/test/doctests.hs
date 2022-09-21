import Test.DocTest
import System.Environment

-- | Expose precompiled library modules.
modules :: [String]
modules =
  [ "-XOverloadedStrings"
  , "DNS/Types.hs"
  ]

main :: IO ()
main = getArgs >>= doctest . (++ modules)
