module DNS.Iterative.Query.StubZone where

-- GHC packages
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

-- other packages

-- dnsext packages
import DNS.Types
import Data.IP (IP (..))

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Class
import DNS.Iterative.Query.ZoneMap

{- FOURMOLU_DISABLE -}
getStubDelegation :: (Domain, [Domain], [Address], MayFilledDS) -> Either String Delegation
getStubDelegation (apex, names, addrs, dsState) =
    maybe (Left $ "stub-zone: zone has empty address or names: " ++ show apex) (pure . mkD) $ nonEmpty es
  where
    mkD ns = Delegation apex ns dsState [] FreshD
    es = [DEstubA4 ne | Just ne <- [nonEmpty [(i, p) | (IPv4 i, p) <- addrs]]] ++
         [DEstubA6 ne | Just ne <- [nonEmpty [(i, p) | (IPv6 i, p) <- addrs]]] ++
         [DEonlyNS n  | n <- names]
{- FOURMOLU_ENABLE -}

stubDomain :: Delegation -> Domain
stubDomain = delegationZone

getStubMap :: [(Domain, [Domain], [Address], MayFilledDS)] -> Either String (Map Domain [Delegation])
getStubMap es = do
    delegations <- mapM getStubDelegation es
    let lats = subdomainSemilatticeOn stubDomain delegations
    pure $ Map.fromList lats

lookupStub :: Map Domain [Delegation] -> Domain -> Maybe Delegation
lookupStub = lookupApexOn stubDomain
