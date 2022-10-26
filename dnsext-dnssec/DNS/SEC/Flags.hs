{-# LANGUAGE BinaryLiterals #-}

module DNS.SEC.Flags where

import DNS.Types.Internal

import DNS.SEC.Imports

data DNSKEY_Flag = ZONE | REVOKE | SecureEntryPoint deriving (Eq, Ord, Show)

toDNSKEYflags :: Word16 -> [DNSKEY_Flag]
toDNSKEYflags w = catMaybes flags
  where
    jst c v = if c then Just v else Nothing
    flags = [ jst (w `testBit` 8) ZONE
            , jst (w `testBit` 7) REVOKE
            , jst (w `testBit` 0) SecureEntryPoint
            ]

fromDNSKEYflags :: [DNSKEY_Flag] -> Word16
fromDNSKEYflags flags = foldl' (.|.) 0 $ map toW flags
  where
    toW ZONE             = 0b0000000100000000
    toW REVOKE           = 0b0000000010000000
    toW SecureEntryPoint = 0b0000000000000001

putDNSKEYflags :: [DNSKEY_Flag] -> SPut
putDNSKEYflags = put16 . fromDNSKEYflags

getDNSKEYflags :: SGet [DNSKEY_Flag]
getDNSKEYflags = toDNSKEYflags <$> get16
