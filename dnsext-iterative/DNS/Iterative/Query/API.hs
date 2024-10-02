{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.API (
    getResponseIterative,
    CacheResult (..),
    getResponseCached,
    getResultIterative,
    getResultCached,
    replyMessage,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls (..),
 )
import qualified DNS.Do53.Client as DNS
import DNS.SEC (TYPE (..))
import DNS.Types hiding (InvalidEDNS)
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Resolve
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils (logQueryErrors)

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

-- | Getting a response corresponding to a query.
--   The cache is maybe updated.
getResponseIterative
    :: Env
    -> DNSMessage
    -> IO (Either String DNSMessage)
getResponseIterative env reqM = case DNS.question reqM of
    [] -> return $ Left "empty question"
    qs@(q : _) -> getResponseIterative' env reqM q qs

getResponseIterative'
    :: Env
    -> DNSMessage
    -> DNS.Question
    -> [DNS.Question]
    -> IO (Either String DNSMessage)
getResponseIterative' env reqM q@(DNS.Question bn typ cls) qs = do
    ers <- runDNSQuery getResult env $ queryContext q (ctrlFromRequestHeader reqF reqEH)
    return $ replyMessage ers (DNS.identifier reqM) qs
  where
    reqF = DNS.flags reqM
    reqEH = DNS.ednsHeader reqM
    prefix = "resp-iterative: orig-query " ++ show bn ++ " " ++ show typ ++ " " ++ show cls ++ ": "
    getResult = logQueryErrors prefix $ do
        guardRequestHeader reqF reqEH
        getResultIterative q

data CacheResult
    = CResultMissHit
    | CResultHit DNSMessage
    | CResultDenied String

toCacheResult :: Either String DNSMessage -> CacheResult
toCacheResult (Left x) = CResultDenied x
toCacheResult (Right x) = CResultHit x

-- | Getting a response corresponding to a query from the cache.
getResponseCached
    :: Env
    -> DNSMessage
    -> IO CacheResult
getResponseCached env reqM = case DNS.question reqM of
    [] -> return $ CResultDenied "empty question"
    qs@(q : _) -> getResponseCached' env reqM q qs

getResponseCached' :: Env -> DNSMessage -> DNS.Question -> [DNS.Question] -> IO CacheResult
getResponseCached' env reqM q@(DNS.Question bn typ cls) qs = do
    ex <- runDNSQuery getResult env $ queryContext q (ctrlFromRequestHeader reqF reqEH)
    case ex of
        Right Nothing -> return CResultMissHit
        Right (Just r) -> return $ toCacheResult $ mkResponse $ Right r
        Left l -> return $ toCacheResult $ mkResponse $ Left l
  where
    reqF = DNS.flags reqM
    reqEH = DNS.ednsHeader reqM
    prefix = "resp-cached: orig-query " ++ show bn ++ " " ++ show typ ++ " " ++ show cls ++ ": "
    getResult = logQueryErrors prefix $ do
        guardRequestHeader reqF reqEH
        getResultCached q
    mkResponse ers = replyMessage ers (DNS.identifier reqM) qs

ctrlFromRequestHeader :: DNSFlags -> EDNSheader -> QueryControls
ctrlFromRequestHeader reqF reqEH = DNS.doFlag doOp <> DNS.cdFlag cdOp <> DNS.adFlag adOp
  where
    doOp
        | dnssecOK = FlagSet
        | otherwise = FlagClear
    cdOp
        | DNS.chkDisable reqF = FlagSet
        | otherwise = FlagClear
    adOp
        | DNS.authenData reqF = FlagSet
        | otherwise = FlagClear

    dnssecOK = case reqEH of
        DNS.EDNSheader edns | DNS.ednsDnssecOk edns -> True
        _ -> False

guardRequestHeader :: DNSFlags -> EDNSheader -> DNSQuery ()
guardRequestHeader reqF reqEH
    | reqEH == DNS.InvalidEDNS =
        throwError $ InvalidEDNS [] DNS.InvalidEDNS DNS.defaultResponse
    | not rd = throwError $ HasError [] DNS.Refused DNS.defaultResponse
    | otherwise = pure ()
  where
    rd = DNS.recDesired reqF

-- | Converting 'QueryError' and 'Result' to 'DNSMessage'.
replyMessage
    :: Either QueryError Result
    -> DNS.Identifier
    -> [DNS.Question]
    -> Either String DNSMessage
replyMessage eas ident rqs =
    either queryError (\(rcode, rrs, auth) -> Right $ message rcode rrs auth) eas
  where
    dnsError de = message <$> rcodeOfDNSError de <*> pure [] <*> pure []
    rcodeOfDNSError e = foldDNSErrorToRCODE (Left $ "DNSError: " ++ show e) Right e

    queryError qe = case qe of
        DnsError e _ -> dnsError e
        NotResponse{} -> Right $ message DNS.ServFail [] []
        InvalidEDNS{} -> Right $ message DNS.ServFail [] []
        HasError _as rc _m -> Right $ message rc [] []
        QueryDenied -> Left "QueryDenied"

    message rcode rrs auth =
        res
            { DNS.identifier = ident
            , DNS.rcode = rcode
            , DNS.flags = f{DNS.authAnswer = False}
            , DNS.answer = rrs
            , DNS.authority = auth
            , DNS.question = rqs
            }
    res = DNS.defaultResponse
    f = DNS.flags res

-- | Getting a response corresponding to 'Domain' and 'TYPE'.
--   The cache is maybe updated.
getResultIterative :: Question -> DNSQuery Result
getResultIterative q = do
    ((cnrrs, _rn), etm) <- resolve q
    reqDO <- asksQC requestDO_
    let fromRRsets = concatMap $ rrListFromRRset reqDO
        fromMessage (msg, vans, vauth) = (DNS.rcode msg, fromRRsets vans, fromRRsets vauth)
    return $ makeResult reqDO cnrrs $ either (resultFromRRS reqDO) fromMessage etm

-- | Getting a response corresponding to 'Domain' and 'TYPE' from the cache.
getResultCached :: Question -> DNSQuery (Maybe Result)
getResultCached q = do
    ((cnrrs, _rn), e) <- resolveByCache q
    reqDO <- asksQC requestDO_
    return $ either (Just . makeResult reqDO cnrrs . resultFromRRS reqDO) (const Nothing) e

makeResult :: RequestDO -> [RRset] -> Result -> Result
makeResult reqDO cnRRset (rcode, ans, auth) =
    ( rcode
    , denyAnswer reqDO $ concat $ map (rrListFromRRset reqDO) cnRRset ++ [ans]
    , allowAuthority reqDO auth
    )
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

resultFromRRS :: RequestDO -> ResultRRS -> Result
resultFromRRS reqDO (rcode, cans, cauth) = (rcode, fromRRsets cans, fromRRsets cauth)
  where
    fromRRsets = concatMap $ rrListFromRRset reqDO

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
