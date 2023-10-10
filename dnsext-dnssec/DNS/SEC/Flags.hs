{-# LANGUAGE BinaryLiterals #-}

module DNS.SEC.Flags where

import DNS.SEC.Imports
import DNS.Types.Internal

data DNSKEY_Flag = ZONE | REVOKE | SecureEntryPoint deriving (Eq, Ord, Show)

toDNSKEYflags :: Word16 -> [DNSKEY_Flag]
toDNSKEYflags w = catMaybes flags
  where
    jst c v = if c then Just v else Nothing
    flags =
        [ jst (w `testBit` 8) ZONE
        , jst (w `testBit` 7) REVOKE
        , jst (w `testBit` 0) SecureEntryPoint
        ]

fromDNSKEYflags :: [DNSKEY_Flag] -> Word16
fromDNSKEYflags flags = foldl' (.|.) 0 $ map toW flags
  where
    toW ZONE = 0b0000000100000000
    toW REVOKE = 0b0000000010000000
    toW SecureEntryPoint = 0b0000000000000001

putDNSKEYflags :: [DNSKEY_Flag] -> Builder ()
putDNSKEYflags fs wbuf _ = put16 wbuf $ fromDNSKEYflags fs

getDNSKEYflags :: Parser [DNSKEY_Flag]
getDNSKEYflags rbuf _ = toDNSKEYflags <$> get16 rbuf

data NSEC3_Flag = OptOut | NSEC3_Flag_Unknown Word8 deriving (Eq, Ord, Show)

toNSEC3flags :: Word8 -> [NSEC3_Flag]
toNSEC3flags w
    {- https://datatracker.ietf.org/doc/html/rfc5155#section-8.2
       "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one." -}
    | w `elem` [0, 1] = catMaybes flags
    | otherwise = [NSEC3_Flag_Unknown w]
  where
    jst c v = if c then Just v else Nothing
    flags =
        [ jst (w `testBit` 0) OptOut
        ]

fromNSEC3flags :: [NSEC3_Flag] -> Word8
fromNSEC3flags flags = foldl' (.|.) 0 $ map toW flags
  where
    toW OptOut = 0b00000001
    toW (NSEC3_Flag_Unknown w) = w

putNSEC3flags :: [NSEC3_Flag] -> Builder ()
putNSEC3flags ns wbuf _ = put8 wbuf $ fromNSEC3flags ns

getNSEC3flags :: Parser [NSEC3_Flag]
getNSEC3flags rbuf _ = toNSEC3flags <$> get8 rbuf
