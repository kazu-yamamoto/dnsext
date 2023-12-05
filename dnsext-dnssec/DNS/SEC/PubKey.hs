module DNS.SEC.PubKey where

import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

data PubKey
    = PubKey_RSA {rsa_size :: Int, rsa_e :: Opaque, rsa_n :: Opaque}
    | PubKey_ECDSA {ecdsa_x :: Opaque, ecdsa_y :: Opaque}
    | PubKey_Opaque {pubkey_opaque :: Opaque}
    deriving (Eq, Ord, Show)

toPubKey :: PubAlg -> Opaque -> PubKey
toPubKey RSAMD5 = toPubKey_RSA
toPubKey RSASHA1 = toPubKey_RSA
toPubKey RSASHA1_NSEC3_SHA1 = toPubKey_RSA {- https://datatracker.ietf.org/doc/html/rfc5155#section-2 -}
toPubKey RSASHA256 = toPubKey_RSA
toPubKey RSASHA512 = toPubKey_RSA
toPubKey ECDSAP256SHA256 = toPubKey_ECDSA 32
toPubKey ECDSAP384SHA384 = toPubKey_ECDSA 48
toPubKey _ = PubKey_Opaque

toPubKey_RSA :: Opaque -> PubKey
toPubKey_RSA o = PubKey_RSA len e n
  where
    (len, e, n) = case Opaque.uncons o of
        Just (0, r0) -> fromJust $ do
            (x, r1) <- Opaque.uncons r0
            (y, r2) <- Opaque.uncons r1
            let elen = 256 * fromIntegral x + fromIntegral y
            return $ divide elen r2
        Just (l, r0) -> divide (fromIntegral l) r0
        _ -> error "toPubKey_RSA"

    divide elen o' =
        let (e', n') = Opaque.splitAt elen o'
         in ( Opaque.length n' * 8
            , e'
            , n'
            )

toPubKey_ECDSA :: Int -> Opaque -> PubKey
toPubKey_ECDSA len o
    | len * 2 == blen =
        let (x, y) = Opaque.splitAt len o
         in PubKey_ECDSA x y
    | otherwise = error "toPubKey_ECDSA"
  where
    blen = Opaque.length o

fromPubKey :: PubKey -> Opaque
fromPubKey (PubKey_RSA _len e n)
    | elen >= 256 =
        let (x, y) = elen `divMod` 256
         in Opaque.concat
                [ Opaque.singleton 0
                , Opaque.singleton $ fromIntegral x
                , Opaque.singleton $ fromIntegral y
                , e
                , n
                ]
    | otherwise =
        Opaque.concat
            [ Opaque.singleton $ fromIntegral elen
            , e
            , n
            ]
  where
    elen = Opaque.length e
fromPubKey (PubKey_ECDSA x y) = x <> y
fromPubKey (PubKey_Opaque o) = o

putPubKey :: PubKey -> Builder ()
putPubKey pub = putOpaque $ fromPubKey pub

getPubKey :: PubAlg -> Int -> Parser PubKey
getPubKey alg len rbuf ref = toPubKey alg <$> getOpaque len rbuf ref
