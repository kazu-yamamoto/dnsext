module DNS.Types.Ext where

import DNS.Types.Dict
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.RData
import DNS.Types.Type

data ExtRR a = ExtRR TYPE String (Proxy a)

extendRR :: ResourceData a => ExtRR a -> IO ()
extendRR (ExtRR typ name proxy) = do
    addRData typ proxy
    addType typ name

data ExtOpt a = ExtOpt OptCode String (Proxy a)

extendOpt :: OptData a => ExtOpt a -> IO ()
extendOpt (ExtOpt code name proxy) = do
    addOData code proxy
    addOpt code name
