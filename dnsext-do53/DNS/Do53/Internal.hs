module DNS.Do53.Internal (
    -- * TCP related
    openTCP
  , sendTCP
  , recvTCP
    -- * Virtual circuit
  , sendVC
  , recvVC
  , encodeVCLength
  , decodeVCLength
    -- * Resolv
  , resolve
  , ResolvEnv(..)
    -- * Resolver information
  , ResolvInfo(..)
  , defaultResolvInfo
  , ResolvActions(..)
  , defaultResolvActions
    -- * Resolver: DNS over X
  , Resolver
  , udpTcpResolver
  , udpResolver
  , tcpResolver
    -- * Resolver for virtual circuit
  , Send
  , Recv
  , vcResolver
    -- * Query
  , encodeQuery
    -- * Generating identifier
  , singleGenId
  , newConcurrentGenId
    -- * Misc
  , checkRespM
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Id
import DNS.Do53.Query
import DNS.Do53.Resolve
import DNS.Do53.Types
