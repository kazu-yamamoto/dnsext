module DNS.SEC.Verify.N3SHA (
    n3sha1,
)
where

-- memory

-- cryptonite
import Crypto.Hash (HashAlgorithm, hashWith)
import Crypto.Hash.Algorithms (SHA1 (..))
import DNS.SEC.Verify.Types
import qualified Data.ByteArray as BA

n3sha1 :: NSEC3Impl
n3sha1 = shaHelper SHA1

shaHelper :: HashAlgorithm hash => hash -> NSEC3Impl
shaHelper hash =
    NSEC3Impl
        { nsec3IGetHash = hashWith hash
        , nsec3IGetBytes = BA.convert
        }
