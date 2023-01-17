module DNS.DoX.Internal (
    SolvInfo(..)
  , getEpochTime
  , tlsSolver
  , quicSolver
  )  where

import DNS.Do53.Internal
import DNS.DoX.QUIC
import DNS.DoX.TLS
