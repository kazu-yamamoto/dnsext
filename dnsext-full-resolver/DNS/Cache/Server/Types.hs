module DNS.Cache.Server.Types (
    Status,
    Server,
    Env,
    HostName,
    PortNumber,
) where

import Network.Socket
import DNS.Cache.Iterative (Env (..))

type Status = [(String, Int)]

type Server = Env -> PortNumber -> HostName -> IO ([IO ()], [IO Status])
