{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.API (
    getReplyMessage,
    CacheResult (..),
    getReplyCached,
    replyMessage,
    replyResult,
    replyResultCached,
) where

-- GHC packages
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (throwE)
import Control.Monad.Trans.Reader (asks)

-- other packages

-- dns packages

import DNS.Do53.Client (
    EdnsControls (..),
    FlagOp (..),
    HeaderControls (..),
    QueryControls (..),
 )
import qualified DNS.Do53.Client as DNS
import DNS.SEC (
    TYPE (DNSKEY, DS, NSEC, NSEC3, RRSIG),
 )
import DNS.Types (
    DNSHeader,
    DNSMessage,
    Domain,
    EDNSheader,
    ResourceRecord (..),
    TYPE (SOA),
 )
import qualified DNS.Types as DNS

-- this package
import DNS.Cache.Iterative.Resolve
import DNS.Cache.Iterative.Types

-- $setup
-- >>> :set -XOverloadedStrings

-----

{- datatypes to propagate request flags -}

data RequestDO
    = DnssecOK
    | NoDnssecOK
    deriving (Show)

data RequestCD
    = CheckDisabled
    | NoCheckDisabled
    deriving (Show)

data RequestAD
    = AuthenticatedData
    | NoAuthenticatedData
    deriving (Show)

{- request flags to pass iterative query.
  * DO (DNSSEC OK) must be 1 for DNSSEC available resolver
    * https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1
  * CD (Checking Disabled)
  * AD (Authenticated Data)
    * https://datatracker.ietf.org/doc/html/rfc6840#section-5.7
      "setting the AD bit in a query as a signal indicating that the requester understands and is interested in the value of the AD bit in the response" -}
requestDO :: QueryControls -> RequestDO
requestDO ic = case extDO $ qctlEdns ic of
    FlagSet -> DnssecOK
    _ -> NoDnssecOK

_requestCD :: QueryControls -> RequestCD
_requestCD ic = case cdBit $ qctlHeader ic of
    FlagSet -> CheckDisabled
    _ -> NoCheckDisabled

_requestAD :: QueryControls -> RequestAD
_requestAD ic = case adBit $ qctlHeader ic of
    FlagSet -> AuthenticatedData
    _ -> NoAuthenticatedData

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバ群の名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバ群の初期値はルートサーバとなる.
 -}

-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

-- | Getting a response.
getReplyMessage
    :: Env
    -> DNSMessage
    -> IO (Either String DNSMessage)
getReplyMessage env reqM = case DNS.question reqM of
    [] -> return $ Left "empty question"
    qs@(q : _) -> getReplyMessage' env reqM q qs

getReplyMessage'
    :: Env
    -> DNSMessage
    -> DNS.Question
    -> [DNS.Question]
    -> IO (Either String DNSMessage)
getReplyMessage' env reqM (DNS.Question bn typ _) qs = do
    ers <- runDNSQuery getResult env $ ctrlFromRequestHeader reqH reqEH
    return $ replyMessage ers (DNS.identifier reqH) qs
  where
    reqH = DNS.header reqM
    reqEH = DNS.ednsHeader reqM
    getResult = do
        guardRequestHeader reqH reqEH
        replyResult bn typ

data CacheResult
    = None
    | Positive DNSMessage
    | Negative String

toCacheResult :: Either String DNSMessage -> CacheResult
toCacheResult (Left x) = Negative x
toCacheResult (Right x) = Positive x

-- | Getting a response from the cache.
getReplyCached
    :: Env
    -> DNSMessage
    -> IO CacheResult
getReplyCached env reqM = case DNS.question reqM of
    [] -> return $ Negative "empty question"
    qs@(q : _) -> getReplyCached' env reqM q qs

getReplyCached'
    :: Env -> DNSMessage -> DNS.Question -> [DNS.Question] -> IO CacheResult
getReplyCached' env reqM (DNS.Question bn typ _) qs = do
    ex <- runDNSQuery getResult env (ctrlFromRequestHeader reqH reqEH)
    case ex of
        Right Nothing -> return None
        Right (Just r) -> return $ toCacheResult $ mkReply $ Right r
        Left l -> return $ toCacheResult $ mkReply $ Left l
  where
    reqH = DNS.header reqM
    reqEH = DNS.ednsHeader reqM
    getResult = do
        guardRequestHeader reqH reqEH
        replyResultCached bn typ
    mkReply ers = replyMessage ers (DNS.identifier reqH) qs

ctrlFromRequestHeader :: DNSHeader -> EDNSheader -> QueryControls
ctrlFromRequestHeader reqH reqEH = DNS.doFlag doOp <> DNS.cdFlag cdOp <> DNS.adFlag adOp
  where
    doOp
        | dnssecOK = FlagSet
        | otherwise = FlagClear
    cdOp
        | dnssecOK, DNS.chkDisable flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear
    adOp
        | dnssecOK, DNS.authenData flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear

    flags = DNS.flags reqH
    dnssecOK = case reqEH of
        DNS.EDNSheader edns | DNS.ednsDnssecOk edns -> True
        _ -> False

guardRequestHeader :: DNSHeader -> EDNSheader -> DNSQuery ()
guardRequestHeader reqH reqEH
    | reqEH == DNS.InvalidEDNS =
        throwE $ InvalidEDNS DNS.InvalidEDNS DNS.defaultResponse
    | not rd = throwE $ HasError DNS.Refused DNS.defaultResponse
    | otherwise = pure ()
  where
    rd = DNS.recDesired $ DNS.flags reqH

-- | Converting 'QueryError' and 'Result' to 'DNSMessage'.
replyMessage
    :: Either QueryError Result
    -> DNS.Identifier
    -> [DNS.Question]
    -> Either String DNSMessage
replyMessage eas ident rqs =
    either queryError (Right . message) eas
  where
    dnsError de = fmap message $ (,,) <$> rcodeDNSError de <*> pure [] <*> pure []
    rcodeDNSError e = case e of
        DNS.RetryLimitExceeded -> Right DNS.ServFail
        DNS.FormatError -> Right DNS.FormatErr
        DNS.ServerFailure -> Right DNS.ServFail
        DNS.NotImplemented -> Right DNS.NotImpl
        DNS.OperationRefused -> Right DNS.ServFail {- like bind9 behavior -}
        DNS.BadOptRecord -> Right DNS.BadVers
        _ -> Left $ "DNSError: " ++ show e

    queryError qe = case qe of
        DnsError e -> dnsError e
        NotResponse{} -> Left "qORr is not response"
        InvalidEDNS{} -> Left "Invalid EDNS"
        HasError rc _m -> Right $ message (rrc, [], [])
          where
            rrc = case rc of
                DNS.Refused -> DNS.ServFail
                _ -> rc

    message (rcode, rrs, auth) =
        res
            { DNS.header =
                h
                    { DNS.identifier = ident
                    , DNS.flags = f{DNS.authAnswer = False, DNS.rcode = rcode}
                    }
            , DNS.answer = rrs
            , DNS.authority = auth
            , DNS.question = rqs
            }
    res = DNS.defaultResponse
    h = DNS.header res
    f = DNS.flags h

-- 反復検索を使って返答メッセージ用の結果コードと応答セクションを得る.
replyResult :: Domain -> TYPE -> DNSQuery Result
replyResult n typ = do
    ((cnrrs, _rn), etm) <- resolve n typ
    reqDO <- lift . lift $ asks requestDO
    let fromRRsets = concatMap $ rrListFromRRset reqDO
        fromMessage (msg, (vans, vauth)) = (DNS.rcode $ DNS.flags $ DNS.header msg, fromRRsets vans, fromRRsets vauth)
    return $ makeResult reqDO cnrrs $ either id fromMessage etm

replyResultCached :: Domain -> TYPE -> DNSQuery (Maybe Result)
replyResultCached n typ = do
    ((cnrrs, _rn), e) <- resolveByCache n typ
    reqDO <- lift . lift $ asks requestDO
    return $ either (Just . makeResult reqDO cnrrs) (const Nothing) e

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

resolveByCache
    :: Domain
    -> TYPE
    -> DNSQuery (([RRset], Domain), Either Result ((), ([RRset], [RRset])))
resolveByCache =
    resolveLogic
        "cache"
        (\_ -> pure ((), ([], [])))
        (\_ _ -> pure ((), Nothing, ([], [])))

rrListFromRRset :: RequestDO -> RRset -> [ResourceRecord]
rrListFromRRset reqDO RRset{..} = case reqDO of
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
        | sig <- rrsGoodSigs
        ]
