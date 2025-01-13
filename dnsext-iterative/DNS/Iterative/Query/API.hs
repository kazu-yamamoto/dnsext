{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.API (
    foldResponseIterative,
    foldResponseIterative',
    foldResponseCached,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls (..),
 )
import qualified DNS.Do53.Client as DNS
import qualified DNS.Log as Log
import DNS.SEC (TYPE (..))
import DNS.Types hiding (InvalidEDNS)
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports hiding (local)
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Local (takeLocalResult)
import DNS.Iterative.Query.Resolve
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils (logLn, pprMessage)

-----

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバ群の名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバ群の初期値はルートサーバとなる.
 -}

-- | Folding a response corresponding to a query. The cache is maybe updated.
foldResponseIterative :: (String -> a) -> (DNSMessage -> a) -> Env -> DNSMessage -> IO a
foldResponseIterative deny reply env reqM =
    foldResponse "resp-queried" deny reply env reqM (resolveStub reply (identifier reqM) (question reqM))

-- | Folding a response corresponding to a query, from questions and control flags. The cache is maybe updated.
foldResponseIterative' :: (String -> a) -> (DNSMessage -> a) -> Env -> Identifier -> [Question] -> Question -> QueryControls -> IO a
foldResponseIterative' deny reply env ident qs q qctl =
    foldResponse' "resp-queried'" deny reply env ident qs q qctl (resolveStub reply ident qs)

resolveStub :: (DNSMessage -> a) -> Identifier -> [Question] -> DNSQuery a
resolveStub reply ident qs = do
    ((cnrrs, _rn), etm) <- resolve =<< asksQP origQuestion_
    reqDO <- asksQP requestDO_
    let result rc vans vauth = replyMessage reqDO cnrrs rc vans vauth ident qs reply
    pure $ either (\(rc, vans, vauth) -> result rc vans vauth) (\(msg, vans, vauth) -> result (rcode msg) vans vauth) etm

-- | Folding a response corresponding to a query from the cache.
foldResponseCached :: DNSQuery a -> (String -> a) -> (DNSMessage -> a) -> Env -> DNSMessage -> IO a
foldResponseCached misshit deny reply env reqM = foldResponse "resp-cached" deny reply env reqM $ do
    ((cnrrs, _rn), m) <- resolveByCache =<< asksQP origQuestion_
    reqDO <- asksQP requestDO_
    let hit (rc, vans, vauth) = replyMessage reqDO cnrrs rc vans vauth (identifier reqM) (question reqM) reply
    maybe misshit (pure . hit) m

replyMessage :: RequestDO -> [RRset] -> RCODE -> [RRset] -> [RRset] -> Identifier -> [Question] -> (DNSMessage -> a) -> a
replyMessage reqDO cnrrs rc vans vauth ident qs k = withResolvedRRs reqDO (cnrrs ++ vans) vauth withDO
  where
    withDO fs ans auth = k $ filterWithDO reqDO (h fs) ans auth
    h fs ans auth = replyDNSMessage ident qs rc fs ans auth

{- FOURMOLU_DISABLE -}
foldResponse
    :: String -> (String -> a) -> (DNSMessage -> a)
    -> Env -> DNSMessage -> DNSQuery a -> IO a
foldResponse name deny reply env reqM@DNSMessage{question=qs,identifier=ident} qaction =
    handleRequest prefix reqM reqerr result
  where
    reqerr = requestError env "" $ \rc -> pure $ reply $ replyDNSMessage ident qs rc resFlags [] []
    result q = foldResponse' name deny reply env ident qs q (ctrlFromRequestHeader reqM) qaction
    prefix = concat pws
    pws = [name ++ ": orig-query " ++ show bn ++ " " ++ show typ ++ " " ++ show cls ++ ": " | Question bn typ cls <- take 1 qs]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
foldResponse'
    :: String -> (String -> a) -> (DNSMessage -> a)
    -> Env -> Identifier -> [Question] -> Question -> QueryControls -> DNSQuery a -> IO a
foldResponse' name deny reply env ident qs q@(Question bn typ cls) qctl qaction  =
    takeLocalResult env q (pure $ deny "local-zone: query-denied") query (pure . local)
  where
    query = either eresult pure =<< runDNSQuery (logQueryErrors prefix qaction) env qparam
    eresult = queryErrorReply ident qs (pure . deny) ereplace
    {- replace response-code only when query, not replace for request-error or local-result -}
    ereplace resM = replaceRCODE env "query-error" (rcode resM) <&> \rc1 -> reply resM{rcode = rc1}
    local (rc, vans, vauth) = withResolvedRRs (requestDO_ qparam) vans vauth h
      where h fs ans = reply . replyDNSMessage ident qs rc fs ans
    qparam = queryParam q qctl
    prefix = name ++ ": orig-query " ++ show bn ++ " " ++ show typ ++ " " ++ show cls ++ ": "
{- FOURMOLU_ENABLE -}

-----

{- FOURMOLU_DISABLE -}
logQueryErrors :: String -> DNSQuery a -> DNSQuery a
logQueryErrors prefix q = do
      handleQueryError left return q
    where
      left qe = do
          logQueryError qe
          throwError qe
      logQueryError qe = case qe of
          DnsError de ss        -> logDnsError de ss
          NotResponse addrs resp msg  -> logNotResponse addrs resp msg
          InvalidEDNS addrs eh msg    -> logInvalidEDNS addrs eh msg
          HasError addrs rcode msg    -> logHasError addrs rcode msg
      logDnsError de ss = case de of
          NetworkFailure {}   -> putLog detail
          DecodeError {}      -> putLog detail
          RetryLimitExceeded  -> putLog detail
          UnknownDNSError {}  -> putLog detail
          _                   -> pure ()
        where detail = show de ++ ": " ++ intercalate ", " ss
      logNotResponse  addrs False  msg  = putLog $ pprAddrs addrs ++ ":\n" ++ pprMessage "not response:" msg
      logNotResponse _addrs True  _msg  = pure ()
      logInvalidEDNS  addrs DNS.InvalidEDNS  msg = putLog $ pprAddrs addrs ++ ":\n" ++ pprMessage "invalid EDNS:" msg
      logInvalidEDNS  _     _               _msg = pure ()
      logHasError _addrs _rcode _msg = pure ()
      pprAddrs = unwords . map show
      putLog = logLn Log.WARN . (prefix ++)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
ctrlFromRequestHeader :: DNSMessage -> QueryControls
ctrlFromRequestHeader DNSMessage{flags=reqF,ednsHeader=reqEH} = DNS.doFlag doF <> DNS.cdFlag cdF <> DNS.adFlag adF
  where
    doF | dnssecOK   = FlagSet
        | otherwise  = FlagClear
    cdF | DNS.chkDisable reqF  = FlagSet
        | otherwise            = FlagClear
    adF | DNS.authenData reqF  = FlagSet
        | otherwise            = FlagClear

    dnssecOK = case reqEH of
        DNS.EDNSheader edns | DNS.ednsDnssecOk edns  -> True
        _                                            -> False
{- FOURMOLU_ENABLE -}

requestError :: Env -> String -> (RCODE -> IO a) -> RCODE -> String -> IO a
requestError env prefix h rc err = logLines_ env Log.WARN Nothing [prefix ++ err] >> h rc

{- FOURMOLU_DISABLE -}
handleRequest :: String -> DNSMessage -> (RCODE -> String -> a) -> (Question -> a) -> a
handleRequest prefix DNSMessage{flags = reqF,ednsHeader=reqEH,question=qs} eh h
    | reqEH == DNS.InvalidEDNS   =       eh' DNS.ServFail   "InvalidEDNS"
    | not (DNS.recDesired reqF)  =       eh' DNS.Refused    "RD flag required"
    | otherwise                  = list (eh' DNS.FormatErr  "empty question") (\q _ -> h q) qs
  where
    eh' rc = eh rc . (("request error: " ++ prefix) ++)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
replaceRCODE :: Env -> String -> RCODE -> IO RCODE
replaceRCODE env tag rc0 = unless (rc0 == rc1) putLog $> rc1
  where
    putLog = logLines_ env Log.INFO Nothing [tag ++ ": replace response-code for query: " ++ show rc0 ++ " -> " ++ show rc1]
    rc1 = case rc0 of
        DNS.Refused  ->  DNS.ServFail
        x            ->  x
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
queryErrorReply :: Identifier -> [Question] -> (String -> a) -> (DNSMessage -> a) -> QueryError -> a
queryErrorReply ident rqs left right qe = case qe of
    DnsError e _        -> dnsError e
    NotResponse{}       -> right $ message DNS.ServFail
    InvalidEDNS{}       -> right $ message DNS.ServFail
    HasError _as rc _m  -> right $ message rc
  where
    dnsError e = foldDNSErrorToRCODE (left $ "DNSError: " ++ show e) (right . message) e
    message rc = replyDNSMessage ident rqs rc resFlags [] []
{- FOURMOLU_ENABLE -}

replyDNSMessage :: Identifier -> [Question] -> RCODE -> DNSFlags -> [RR] -> [RR] -> DNSMessage
replyDNSMessage ident rqs rcode flags rrs auth =
    res
        { DNS.identifier = ident
        , DNS.rcode = rcode
        , DNS.flags = flags
        , DNS.answer = rrs
        , DNS.authority = auth
        , DNS.question = rqs
        }
  where
    res = DNS.defaultResponse

filterWithDO :: RequestDO -> ([RR] -> [RR] -> a) -> ([RR] -> [RR] -> a)
filterWithDO reqDO k2 ans auth =
    k2 (denyAnswer reqDO ans) (allowAuthority reqDO auth)
  where
    denyAnswer DnssecOK rrs = rrs
    denyAnswer NoDnssecOK rrs = foldr takeNODNSSEC [] rrs
      where
        takeNODNSSEC rr@ResourceRecord{..} xs
            | rrtype `elem` dnssecTypes = xs
            | otherwise = rr : xs

    allowAuthority NoDnssecOK = foldr takeSOA []
      where
        takeSOA rr@ResourceRecord{rrtype = SOA} xs = rr : xs
        takeSOA _ xs = xs
    allowAuthority DnssecOK = foldr takeAuth []
      where
        allowTypes = SOA : dnssecTypes
        takeAuth rr@ResourceRecord{..} xs
            | rrtype `elem` allowTypes = rr : xs
            | otherwise = xs

    dnssecTypes = [DNSKEY, DS, RRSIG, NSEC, NSEC3]

{- FOURMOLU_DISABLE -}
withResolvedRRs :: RequestDO -> [RRset] -> [RRset] -> (DNSFlags -> [RR] -> [RR] -> a) -> a
withResolvedRRs reqDO ans auth h = h resFlags{authenData = allValid} (fromRRsets ans) (fromRRsets auth)
  where
    fromRRsets = concatMap $ rrListFromRRset reqDO
    allValid = not (null rrsets) && all rrsetValid rrsets
    rrsets = ans ++ auth
{- FOURMOLU_ENABLE -}

rrListFromRRset :: RequestDO -> RRset -> [ResourceRecord]
rrListFromRRset reqDO rs@RRset{..} = case reqDO of
    NoDnssecOK -> rrs
    DnssecOK -> case rrsRDatas of
        [] -> []
        _ : _ -> rrs ++ sigs
  where
    rrs =
        [ ResourceRecord rrsName rrsType rrsClass rrsTTL rd
        | rd <- rrsRDatas
        ]
    sigs =
        [ ResourceRecord rrsName RRSIG rrsClass rrsTTL (DNS.toRData sig)
        | sig <- rrsetGoodSigs rs
        ]

{- FOURMOLU_DISABLE -}
resFlags :: DNSFlags
resFlags =
    DNSFlags
    { isResponse    = True
    , authAnswer    = False
    , trunCation    = False
    , recDesired    = False
    , recAvailable  = True
    , authenData    = False
    , chkDisable    = False
    }
{- FOURMOLU_ENABLE -}
