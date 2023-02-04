module DNS.Do53.Internal (
    -- * IO types
    Recv
  , RecvN
  , RecvMany
  , RecvManyN
  , Send
  , SendMany
    -- * TCP related
  , openTCP
  , sendTCP
  , recvTCP
    -- * Virtual circuit
  , sendVC
  , recvVC
  , encodeVCLength
  , decodeVCLength
    -- * Making recvMany
  , recvManyN
  , recvManyNN
    -- * Resolv
  , resolve
  , ResolvEnv(..)
    -- * Resolver information
  , ResolvInfo(..)
  , defaultResolvInfo
  , ResolvActions(..)
  , defaultResolvActions
    -- * Resolver: DNS over X
  , Result(..)
  , toResult
  , Reply(..)
  , Resolver
  , udpTcpResolver
  , udpResolver
  , tcpResolver
    -- * Resolver for virtual circuit
  , vcResolver
    -- * Query
  , encodeQuery
    -- * Generating identifier
  , singleGenId
  , newConcurrentGenId
    -- * Misc
  , checkRespM
  , UDPRetry
  , VCLimit
  , LookupEnv(..)
  , modifyLookupEnv
  , withLookupConfAndResolver
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Id
import DNS.Do53.Lookup
import DNS.Do53.Query
import DNS.Do53.Resolve
import DNS.Do53.Types
