module DNS.Cache.Server.Types (
    Status,
    Server,
    Env,
    HostName,
    PortNumber,
) where

import DNS.Cache.Iterative (Env (..))
import Network.Socket

type Status = [(String, Int)]

type Server = Env -> PortNumber -> HostName -> IO ([IO ()], [IO Status])
