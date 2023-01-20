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
    -- * Resolver: DNS over X
  , ResolvInfo(..)
  , defaultResolvInfo
  , Resolver
  , Send
  , Recv
  , udpTcpResolver
  , udpResolver
  , tcpResolver
  , vcResolver
  , checkRespM
    -- * Misc
  , getEpochTime
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Resolve
import DNS.Do53.Types
