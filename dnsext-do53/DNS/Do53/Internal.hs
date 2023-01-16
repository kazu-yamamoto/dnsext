module DNS.Do53.Internal (
    openTCP
    -- * Receiving DNS messages
  , recvTCP
  , recvVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , sendTCP
  , sendVC
  , encodeVCLength
    -- * Solver: DNS over X
  , SolvInfo(..)
  , Solver
  , udpTcpSolver
  , udpSolver
  , tcpSolver
    -- * ResolvConf
  , ResolvConf(..)
  , getEpochTime
    -- * Resolver
  , Resolver(..)
  ) where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Types
