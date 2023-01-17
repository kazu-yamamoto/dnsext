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
    -- * Resolver
  , Resolver(..)
  , Cache
    -- * Solver: DNS over X
  , vcSolver
  , SolvInfo(..)
  , Solver
  , Send
  , Recv
  , udpTcpSolver
  , udpSolver
  , tcpSolver
  , checkRespM
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Types
