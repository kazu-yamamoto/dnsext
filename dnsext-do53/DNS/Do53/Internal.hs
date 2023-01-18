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
    -- * Seeds
  , Seeds(..)
  , Cache
    -- * Resolver: DNS over X
  , vcResolver
  , ResolvInfo(..)
  , Resolver
  , Send
  , Recv
  , udpTcpResolver
  , udpResolver
  , tcpResolver
  , checkRespM
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Types
