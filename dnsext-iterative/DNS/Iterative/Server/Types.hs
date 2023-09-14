module DNS.Iterative.Server.Types (
    Status,
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
) where

import DNS.Iterative.Query (Env)
import Network.Socket

type Status = [(String, Int)]

type Server = Env -> PortNumber -> HostName -> IO ([IO ()], [IO Status])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    }
