module DNS.Iterative.Query.ZoneMap where

-- GHC packages
import Data.Map (Map)
import qualified Data.Map.Strict as Map

-- dnsext packages
import DNS.Types

-- this package
import DNS.Iterative.Imports

-- $setup
-- >>> :seti -XOverloadedStrings

{- FOURMOLU_DISABLE -}
-- |
-- >>> subdomainSemilatticeOn id []
-- []
-- >>> subdomainSemilatticeOn id ["example.", "b.example.", "a.example."]
-- [("example.",["b.example.","a.example.","example."])]
-- >>> subdomainSemilatticeOn id ["example.", "b.example.", "a.example.", "a.example.com.", "example.com."]
-- [("example.com.",["a.example.com.","example.com."]),("example.",["b.example.","a.example.","example."])]
subdomainSemilatticeOn :: (a -> Domain) -> [a] -> [(Domain, [a])]
subdomainSemilatticeOn f = unfoldr subdoms . sortOn f
  where
    subdoms []      = Nothing
    subdoms (x:xs)  = Just ((fx, reverse hd), tl)  {- check target between smallest and largest in sub-domain lattice -}
      where
        fx = f x
        (hd, tl) = span ((`isSubDomainOf` fx) . f) $ x : xs
{- FOURMOLU_ENABLE -}

-- |
-- >>> semilattice xs = Map.fromList $ subdomainSemilatticeOn id xs
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "xexample."
-- Nothing
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "example."
-- Just "example."
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "x.a.example."
-- Just "example."
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "a.s.example."
-- Just "s.example."
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "a.t.example."
-- Just "example."
-- >>> lookupApexOn id (semilattice ["example.", "s.example", "example.com."]) "a.example.com."
-- Just "example.com."
lookupApexOn :: (a -> Domain) -> Map Domain [a] -> Domain -> Maybe a
lookupApexOn f aMap dom = do
    (_super, subs) <- Map.lookupLE dom aMap
    find ((dom `isSubDomainOf`) . f) subs
