{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Local where

-- dnsext packages
import DNS.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.LocalZone (lookupApex, lookupName)
import DNS.Iterative.Query.Rev

{- FOURMOLU_DISABLE -}
takeLocalResult :: Env -> Question -> DNSQuery (Maybe ResultRRS)
takeLocalResult Env{localZones_ = (apexes, names)} q@(Question dom _ cls)
    | cls /= IN                          = pure Nothing  {- not support other than IN -}
    | Just apex <- lookupApex apexes dom = maybe (throwError QueryDenied) (pure . Just) $ lookupName names apex q
    | otherwise                          = pure $ takeSpecialRevDomainResult dom
{- FOURMOLU_ENABLE -}
