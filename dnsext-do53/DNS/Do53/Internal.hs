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
    -- * ResolvConf
  , ResolvConf(..)
  , getEpochTime
    -- * Lookup
  , LookupEnv(..)
  , Cache
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
  , makeIdGenerators
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Lookup
import DNS.Do53.Memo
import DNS.Do53.Resolve
import DNS.Do53.Types
