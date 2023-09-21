module DNS.Iterative.Server.Types (
    Stats(..),
    defaultStats,
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
) where

import DNS.Iterative.Query (Env)
import Network.Socket

data Stats = Stats
    { statsHit :: Int
    , statsMiss :: Int
    , statsFail :: Int
    }

defaultStats :: Stats
defaultStats = Stats 0 0 0

instance Semigroup Stats where
    (Stats h0 m0 f0) <> (Stats h1 m1 f1) = Stats (h0 + h1) (m0 + m1) (f0 + f1)

instance Monoid Stats where
    mempty = defaultStats

type Server = Env -> PortNumber -> HostName -> IO ([IO ()], [IO Stats])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    }
