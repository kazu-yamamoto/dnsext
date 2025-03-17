{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Local where

-- dnsext packages
import DNS.Types

-- this package
import DNS.Iterative.Query.LocalZone (lookupApex, lookupName)
import DNS.Iterative.Query.Types

{- FOURMOLU_DISABLE -}
takeLocalResult :: Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalResult Env{localZones_ = (apexes, names)} q@(Question dom _ _) denied nothing just
    | Just apex <- lookupApex apexes dom = maybe denied just $ lookupName names apex q
    | otherwise                          = nothing
{- FOURMOLU_ENABLE -}
