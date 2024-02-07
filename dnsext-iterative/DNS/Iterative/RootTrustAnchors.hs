{-# LANGUAGE OverloadedStrings #-}

module DNS.Iterative.RootTrustAnchors (
    rootSepDS,
    getRootSep,
) where

import DNS.Types
import DNS.SEC
import qualified DNS.Types.Opaque as Opaque
import DNS.ZoneFile (Record (R_RR))
import qualified DNS.ZoneFile as Zone

{- import trust-anchor DS RData from
   https://data.iana.org/root-anchors/root-anchors.xml -}
rootSepDS :: RD_DS
rootSepDS = RD_DS 20326 RSASHA256 SHA256 digest
  where
    digest =
        either (error . ("rootSepDS: bad configuration: " ++)) id $
            Opaque.fromBase16
                "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

{- FOURMOLU_DISABLE -}
getRootSep :: FilePath -> IO ([RD_DNSKEY], [RD_DS])
getRootSep path = do
    rs <- Zone.parseFile path
    let rrs = [ rr | R_RR rr <- rs ]
        keys = [ ky | rr@ResourceRecord{ rrname = ".", rrtype = DNSKEY } <- rrs, Just ky <- [fromRData $ rdata rr] ]
        dss  = [ ds | rr@ResourceRecord{ rrname = ".", rrtype = DS }     <- rrs, Just ds <- [fromRData $ rdata rr] ]
    pure (keys, dss)
{- FOURMOLU_ENABLE -}
