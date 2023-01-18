module DNS.DoX.Internal (
    SolvInfo(..)
  , getEpochTime
  , http2Solver
  , http3Solver
  , tlsSolver
  , quicSolver
  )  where

import DNS.Do53.Internal
import DNS.DoX.HTTP2
import DNS.DoX.HTTP3
import DNS.DoX.QUIC
import DNS.DoX.TLS
