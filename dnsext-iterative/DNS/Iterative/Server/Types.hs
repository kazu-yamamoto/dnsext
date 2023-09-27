module DNS.Iterative.Server.Types (
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
) where

import DNS.Iterative.Query (Env)
import Network.Socket

type Server = Env -> PortNumber -> HostName -> IO ([IO ()])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    }
