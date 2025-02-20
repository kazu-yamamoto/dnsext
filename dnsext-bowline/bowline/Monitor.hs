{-# LANGUAGE RecordWildCards #-}

module Monitor (
    monitor,
) where

-- GHC packages
import Control.Applicative ((<|>))
import Control.Concurrent (forkFinally, getNumCapabilities, threadWaitRead)
import Control.Concurrent.Async (waitSTM)
import Control.Concurrent.STM (STM, atomically)
import Control.Exception (SomeException, try)
import Control.Monad
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Char (toUpper)
import Data.Functor (($>))
import Data.List (find, isInfixOf)
import System.IO (
    Handle,
    IOMode (ReadWriteMode),
    hClose,
    hFlush,
    hGetLine,
    hIsEOF,
    hPutStr,
    hPutStrLn,
    stdin,
    stdout,
 )
import Text.Read (readMaybe)

-- dnsext-* packages
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server (withLocationIOE)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import qualified DNS.ThreadStats as TStat
import DNS.Types (Domain, TYPE, Question (..), toRepresentation)
import qualified DNS.Types as DNS
import DNS.Types.Time (EpochTime)
import qualified Network.Socket as S

-- other packages
import Network.Socket (
    AddrInfo (..),
    SockAddr,
    SocketOption (SockOpt, KeepAlive),
    Socket,
    SocketType (Stream),
 )
import System.Posix (getEffectiveGroupID, getEffectiveUserID)

-- this package
import Config
import SockOpt
import SocketUtil (ainfosSkipError)
import Types (CacheControl (..), Control (..), QuitCmd (..), quitCmd)

monitorSockets :: S.PortNumber -> [S.HostName] -> IO [(Socket, SockAddr)]
monitorSockets port = mapM aiSocket <=< ainfosSkipError putStrLn Stream port
  where
    aiSocket ai =
        (,)
            <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
            <*> pure (addrAddress ai)

data Command
    = Param
    | EParam
    | Find [String]
    | Lookup Domain TYPE
    | Stats
    | WStats
    | TStats [String]
    | Expire EpochTime
    | Flush Domain
    | FlushType Domain TYPE
    | FlushBogus
    | FlushNegative
    | FlushAll
    | ReopenLog
    | Noop
    | Exit
    | QuitCmd QuitCmd
    | Help (Maybe String)
    deriving (Show)

{- FOURMOLU_DISABLE -}
monitor
    :: Config
    -> Env
    -> Control
    -> [String]
    -> IO [IO ()]
monitor conf env mng@Control{..} srvInfo = do
    let monPort' = fromIntegral $ cnf_monitor_port conf
    ps <- monitorSockets monPort' $ cnf_monitor_addrs conf
    let monInfo = ["monitor: " ++ show a ++ kaInfo | (_, a) <- ps]
    mapM_ servSock ps
    return $ [runStdConsole monInfo | cnf_monitor_stdio conf] ++ [monitorServer monInfo s | (s, _) <- ps]
  where
    kaInfo = " " ++ unwords (("<keepalive-" ++ keepAliveAvail "no-avail" "enabled" ++ ">") : kaNoAvails)
    kaNoAvails = keepAliveAvail ("no-avail sockopts:" : map show keepNotAvails) []
    runStdConsole monInfo = console conf env mng srvInfo monInfo stdin stdout "<std>"
    logLn level = logLines_ env level Nothing . (: [])
    handle :: (SomeException -> IO a) -> IO a -> IO a
    handle onError = either onError return <=< try
    v6only  sock  S.SockAddrInet6 {} = S.setSocketOption sock S.IPv6Only 1
    v6only _sock  _                  = pure ()
    servSock (sock, a) = withLocationIOE (show a ++ "/mon") $ do
        v6only sock a
        S.setSocketOption sock S.ReuseAddr 1
        keepAliveAvail (pure ()) (setSocketKeepAlive sock $ cnf_monitor_keep_interval conf)
        S.bind sock a
    monitorServer monInfo s = do
        let step = do
                socketWaitRead s
                (sock, addr) <- S.accept s
                sockh <- S.socketToHandle sock ReadWriteMode
                let repl = console conf env mng srvInfo monInfo sockh sockh $ show addr
                void $ forkFinally repl (\_ -> hClose sockh)
            loop =
                either (const $ return ()) (const loop)
                    =<< withWait
                        waitQuit
                        (handle (logLn Log.DEBUG . ("monitor io-error: " ++) . show) step)
        S.listen s 5
        loop
{- FOURMOLU_ENABLE -}

setSocketKeepAlive :: Socket -> Int -> IO ()
setSocketKeepAlive sock interval = do
    S.setSocketOption sock TcpKeepIdle interval
    S.setSocketOption sock TcpKeepInterval interval
    S.setSocketOption sock KeepAlive 1

keepAliveAvail :: a -> a -> a
keepAliveAvail na av
    | not avail = na
    | otherwise = av
  where
    avail = null keepNotAvails

{- FOURMOLU_DISABLE -}
keepNotAvails :: [SocketOption]
keepNotAvails = foldr addAvail [] [KeepAlive, TcpKeepIdle, TcpKeepInterval]
  where
    addAvail so@(SockOpt lv nm) us
        | lv >= 0 && nm >= 0  = us
        | otherwise           = so : us
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
console
    :: Config -> Env -> Control -> [String]
    -> [String] -> Handle -> Handle -> String -> IO ()
console conf env ctl@Control{cacheControl=CacheControl{..},..} srvInfo monInfo inH outH ainfo = do
    let input = do
            s <- hGetLine inH
            let err = hPutStrLn outH ("monitor error: " ++ ainfo ++ ": command parse error: " ++ show s)
            maybe (err $> False) runCmd $ parseCmd $ words s

        step = do
            eof <- hIsEOF inH
            if eof then return True else input

        repl = do
            hPutStr outH "monitor> " *> hFlush outH
            either (const $ return ()) (\exit -> unless exit repl) =<< withWait waitQuit (handle (($> False) . print) step)

    mapM_ outLn =<< getShowParam'
    repl
  where
    handle :: (SomeException -> IO a) -> IO a -> IO a
    handle onError = either onError return <=< try

    parseTYPE s =
        find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1 .. 512]

    nomalizec c
        | c == '-'   = '_'
        | otherwise  = c
    parseCmd  []       = Just Noop
    parseCmd (cmd:as)  = case map nomalizec cmd:as of
        "param"           : _             -> Just   Param
        "find"            : _             -> Just $ Find as
        "lookup"          : n  : typ : _  -> Lookup (DNS.fromRepresentation n) <$> parseTYPE typ
        "stats"           : _             -> Just   Stats
        "t"               : _             -> Just $ TStats as
        "tstats"          : _             -> Just $ TStats as
        "w"               : _             -> Just   WStats
        "wstats"          : _             -> Just   WStats
        "expire"          : []            -> Just $ Expire 0
        "expire"          : x  : _        -> Expire <$> readMaybe x
        "flush"           : n  : _        -> Just $ Flush $ DNS.fromRepresentation n
        "flush_type"      : n  : ty : _   -> FlushType (DNS.fromRepresentation n) <$> readMaybe ty
        "flush_bogus"     : _             -> Just   FlushBogus
        "flush_negative"  : _             -> Just   FlushNegative
        "flush_all"       : _             -> Just   FlushAll
        "reopen_log"      : _             -> Just   ReopenLog
        "exit"            : _             -> Just   Exit
        "reload"          : _             -> Just $ QuitCmd Reload
        "keep_cache"      : _             -> Just $ QuitCmd KeepCache
        "quit_server"     : _             -> Just $ QuitCmd Quit
        "help"            : w  : _        -> Just $ Help $ Just w
        "help" : []                       -> Just $ Help   Nothing
        _ : _                             -> Nothing

    getShowParam' = getShowParam conf srvInfo monInfo
    outLn = hPutStrLn outH

    runCmd (QuitCmd qcmd) = quitCmd ctl qcmd $> True
    runCmd  Exit = return True
    runCmd cmd = dispatch cmd $> False
      where
        dispatch  Param = mapM_ outLn =<< getShowParam'
        dispatch  Noop = return ()
        dispatch (Find ws) = do
            now <- currentSeconds_ env
            let showDump1 (Question{..}, (ts, Cache.Val rd rk)) =
                    unwords [toRepresentation qname, show qtype, show qclass, show (ts - now), show (rd, rk)]
            mapM_ outLn . filter (ws `allInfixOf`) . map showDump1 . Cache.dump =<< getCache_ env
        dispatch (Lookup dom typ) = print cmd *> (maybe (outLn "miss.") hit =<< lookupCache)
          where
            lookupCache = do
                let lk cache now = Cache.lookup now dom typ DNS.IN cache
                lk <$> getCache_ env <*> currentSeconds_ env
            hit (rrs, rank) = mapM_ outLn $ ("hit: " ++ show rank) : map show rrs
        dispatch  Stats = toLazyByteString <$> getStats >>= BL.hPutStrLn outH
        dispatch (TStats ws) = hPutStrLn outH . unlines . filter (ws `allInfixOf`) =<< TStat.dumpThreads
        dispatch  WStats = toLazyByteString <$> getWStats >>= BL.hPutStrLn outH
        dispatch (Expire offset) = expireCache_ env . (+ offset) =<< currentSeconds_ env
        dispatch (Flush n) = ccRemove n *> hPutStrLn outH "done."
        dispatch (FlushType n ty) = ccRemoveType n ty *> hPutStrLn outH "done."
        dispatch  FlushBogus      = ccRemoveBogus *> hPutStrLn outH "done."
        dispatch  FlushNegative   = ccRemoveNegative *> hPutStrLn outH "done."
        dispatch  FlushAll        = ccClear *> hPutStrLn outH "done."
        dispatch  ReopenLog = reopenLog *> hPutStrLn outH "done."
        dispatch (Help w) = printHelp w
        dispatch  x = outLn $ "command: unknown state: " ++ show x
        allInfixOf ws = and . mapM isInfixOf ws

    printHelp mw = case mw of
        Nothing -> hPutStr outH $ unlines [showHelp h | (_, h) <- helps]
        Just w ->
            maybe (outLn $ "unknown command: " ++ w) (outLn . showHelp) $ lookup w helps
      where
        showHelp (syn, msg) = syn ++ replicate (width - length syn) ' ' ++ " - " ++ msg
        width = 20
        helps =
            [ ("param",           ("param", "show server parameters"))
            , ("find",            ("find [WORD]..", "find dumped cache including words"))
            , ("lookup",          ("lookup DOMAIN TYPE", "lookup cache"))
            , ("stats",           ("stats", "show current server stats"))
            , ("tstats",          ("tstats [WORD]..", "show worker thread status including words"))
            , ("wstats",          ("wstats", "show worker thread status"))
            , ("expire",          ("expire [SECONDS]", "expire cache at the time SECONDS later"))
            , ("flush",           ("flush DOMAIN", "remove DOMAIN rrsets with several types from cache"))
            , ("flush_type",      ("flush DOMAIN TYPE", "remove rrset with DOMAIN and TYPE from cache"))
            , ("flush_bogus",     ("flush_bogus", "remove all bogus cache"))
            , ("flush_negative",  ("flush_negative", "remove all negative cache"))
            , ("flush_all",       ("flush_all", "remove all cache"))
            , ("reopen_log",      ("reopen_log", "reopen logfile when file logging"))
            , ("exit",            ("exit", "exit this management session"))
            , ("reload",          ("reload", "reload this server, flush cache"))
            , ("keep_cache",      ("keep_cache", "reload this server, with keeping cache"))
            , ("quit_server",     ("quit_server", "quit this server"))
            , ("help",            ("help", "show this help"))
            ]
{- FOURMOLU_ENABLE -}

withWait :: STM a -> IO b -> IO (Either a b)
withWait qstm blockAct =
    TStat.withAsync "monitor" blockAct $ \a ->
        atomically $
            (Left <$> qstm)
                <|> (Right <$> waitSTM a)

socketWaitRead :: Socket -> IO ()
socketWaitRead sock = S.withFdSocket sock $ threadWaitRead . fromIntegral

{- FOURMOLU_DISABLE -}
getShowParam :: Config -> [String] -> [String] -> IO [String]
getShowParam conf srvInfo monInfo =
    format <$> sequence
        [ ("capabilities: " ++) . show <$> getNumCapabilities
        , ("euid: " ++) . show <$> getEffectiveUserID
        , ("egid: " ++) . show <$> getEffectiveGroupID
        ]
  where
    format rtInfo =
        [ "---------- configs  ----------" ] ++
        showConfig conf                      ++
        [ "---------- runtime  ----------" ] ++
        srvInfo                              ++
        monInfo                              ++
        rtInfo
{- FOURMOLU_ENABLE -}
