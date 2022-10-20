module DNS.Types.Ext where

import DNS.Types.Dict
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.RData
import DNS.Types.Type

extendRR :: ResourceData a => TYPE -> String -> Proxy a -> IO ()
extendRR typ name proxy = do
    addRData typ proxy
    addType typ name

extendOpt :: OptData a => OptCode -> String -> Proxy a -> IO ()
extendOpt code name proxy = do
    addOData code proxy
    addOpt code name
