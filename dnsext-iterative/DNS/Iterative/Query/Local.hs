{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Local where

-- dnsext packages
import DNS.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Rev

{- FOURMOLU_DISABLE -}
takeLocalResult :: Env -> Question -> DNSQuery (Maybe ResultRRS)
takeLocalResult Env{..} q@(Question dom _ cls)
    | cls /= IN                          = pure Nothing  {- not support other than IN -}
    | Just apex <- lookupLocalApex_ dom  = maybe (throwE QueryDenied) (pure . Just) $ lookupLocalDomain_ apex q
    | otherwise                          = pure $ takeSpecialRevDomainResult dom
{- FOURMOLU_ENABLE -}
