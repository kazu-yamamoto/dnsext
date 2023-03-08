{-# LANGUAGE OverloadedStrings #-}

module DNS.Cache.Iterative (
  -- * resolve interfaces
  getReplyMessage,
  getReplyCached,
  runResolve,
  runResolveJust,
  newEnv,
  runIterative,
  rootHint, rootNS, Delegation,
  QueryError (..),
  printResult,
  -- * types
  NE,
  UpdateCache,
  TimeCache,
  Result,
  -- * low-level interfaces
  DNSQuery, runDNSQuery,
  replyMessage, replyResult, replyResultCached,
  resolve, resolveJust, iterative,
  Env (..),
  ) where

-- GHC packages
import Control.Applicative ((<|>))
import Control.Arrow ((&&&), first)
import qualified Control.Exception as E
import Control.Monad (when, unless, join, guard)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import DNS.Types.Decode (EpochTime)
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Short as Short
import Data.Function (on)
import Data.Functor (($>))
import Data.List (uncons, groupBy, sortOn, sort, intercalate)
import qualified Data.List as L
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (listToMaybe, isJust, fromMaybe)
import qualified Data.Set as Set
import Numeric (readDec, readHex, showHex)

-- other packages
import System.Random (randomR, getStdRandom)

-- dns packages
import Data.IP (IP (IPv4, IPv6), IPv4, IPv6, toIPv4 , toIPv6b)
import qualified Data.IP as IP
import DNS.Types
  (Domain, DNSError, TTL,
   TYPE(A, NS, AAAA, CNAME, SOA), ResourceRecord (..),
   RCODE, DNSHeader, DNSMessage, classIN, Question(..))
import qualified DNS.Types as DNS
import DNS.SEC (TYPE (DNSKEY, DS, RRSIG), RD_DNSKEY, RD_DS (..), RD_RRSIG)
import qualified DNS.SEC.Verify as SEC
import DNS.Do53.Client (FlagOp (..), defaultResolvActions, ractionGenId, ractionGetTime )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (ResolvInfo(..), ResolvEnv(..), udpTcpResolver, defaultResolvInfo, newConcurrentGenId)
import qualified DNS.Do53.Internal as DNS
import DNS.Do53.Memo
  (Ranking (RankAdditional), rankedAnswer, rankedAuthority, rankedAdditional,
   insertSetFromSection, insertSetEmpty, Key, CRSet, Cache)
import qualified DNS.Do53.Memo as Cache

-- this package
import DNS.Cache.RootServers (rootServers)
import DNS.Cache.Types (NE)
import qualified DNS.Cache.Log as Log

-----

data Env =
  Env
  { logLines_ :: Log.Level -> [String] -> IO ()
  , disableV6NS_ :: !Bool
  , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
  , getCache_ :: IO Cache
  , currentSeconds_ :: IO EpochTime
  , timeString_ :: IO ShowS
  , idGen_ :: IO DNS.Identifier
  }

data QueryError
  = DnsError DNSError
  | NotResponse DNS.QorR DNSMessage
  | InvalidEDNS DNS.EDNSheader DNSMessage
  | HasError DNS.RCODE DNSMessage
  deriving Show

type ContextT = ReaderT Env
type DNSQuery = ExceptT QueryError (ContextT IO)

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

type UpdateCache =
  (Key -> TTL -> CRSet -> Ranking -> IO (),
   IO Cache)
type TimeCache = (IO EpochTime, IO ShowS)

newEnv :: (Log.Level -> [String] -> IO ()) -> Bool -> UpdateCache -> TimeCache
       -> IO Env
newEnv putLines disableV6NS (ins, getCache) (curSec, timeStr) = do
  genId <- newConcurrentGenId
  let cxt = Env
        { logLines_ = putLines, disableV6NS_ = disableV6NS
        , insert_ = ins, getCache_ = getCache
        , currentSeconds_ = curSec, timeString_ = timeStr, idGen_ = genId }
  return cxt

dnsQueryT :: (Env -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT = ExceptT . ReaderT

runDNSQuery :: DNSQuery a -> Env -> IO (Either QueryError a)
runDNSQuery = runReaderT . runExceptT

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
  | DNS.qOrR flags /= DNS.QR_Response      =  e $ NotResponse (DNS.qOrR flags) msg
  | DNS.ednsHeader msg == DNS.InvalidEDNS  =  e $ InvalidEDNS (DNS.ednsHeader msg) msg
  | DNS.rcode flags `notElem`
    [DNS.NoErr, DNS.NameErr]               =  e $ HasError (DNS.rcode flags) msg
  | otherwise                              =  f msg
  where
    flags = DNS.flags $ DNS.header msg
-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

-- 返答メッセージを作る
getReplyMessage :: Env -> DNSHeader -> NE DNS.Question -> IO (Either String DNSMessage)
getReplyMessage cxt reqH qs@(DNS.Question bn typ _, _) =
  (\ers -> replyMessage ers (DNS.identifier reqH) $ uncurry (:) qs)
  <$> runDNSQuery (getResult bn) cxt
  where
    getResult n = do
      guardRequestHeader reqH
      replyResult n typ

-- キャッシュから返答メッセージを作る
-- Nothing のときキャッシュ無し
-- Just Left はエラー
getReplyCached :: Env -> DNSHeader -> (DNS.Question, [DNS.Question]) -> IO (Maybe (Either String DNSMessage))
getReplyCached cxt reqH qs@(DNS.Question bn typ _, _) =
  fmap mkReply . either (Just . Left) (Right <$>)
  <$> runDNSQuery (getResult bn) cxt
  where
    getResult n = do
      guardRequestHeader reqH
      replyResultCached n typ
    mkReply ers = replyMessage ers (DNS.identifier reqH) (uncurry (:) qs)

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])

-- 最終的な解決結果を得る
runResolve :: Env -> Domain -> TYPE
           -> IO (Either QueryError (([ResourceRecord] -> [ResourceRecord], Domain), Either Result DNSMessage))
runResolve cxt n typ = runDNSQuery (resolve n typ) cxt

-- 権威サーバーからの解決結果を得る
runResolveJust :: Env -> Domain -> TYPE -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust cxt n typ = runDNSQuery (resolveJust n typ) cxt

-- 反復後の委任情報を得る
runIterative :: Env -> Delegation -> Domain -> IO (Either QueryError Delegation)
runIterative cxt sa n = runDNSQuery (iterative sa n) cxt

-----

-- | parse IPv4 8bit-parts from reverse-lookup domain
--
-- >>> parseV4RevDomain "1.2.3.4.in-addr.arpa."
-- Right [4,3,2,1]
parseV4RevDomain :: Domain -> Either String [Int]
parseV4RevDomain dom = do
  rparts <- maybe (throw "suffix does not match") Right $ L.stripPrefix sufV4 $ reverse $ DNS.toWireLabels dom
  let plen = length rparts
  maybe (throw $ "invalid number of parts split by dot: " ++ show rparts) Right
    $ guard (1 <= plen && plen <= 4)
  mapM getByte rparts
  where
    throw = Left . ("v4Rev: " ++)
    getByte s = do
      byte <- case [ x | (x, "")  <- readDec $ B8.unpack (Short.fromShort s) ] of
                []    ->  throw $ "cannot parse decimal from part: " ++ show s
                [x]   ->  Right x
                _:_   ->  throw $ "ambiguous parse result of decimal part: " ++ show s
      maybe (throw $ "decimal part '" ++ show byte ++ "' is out of range") Right
        $ guard (0 <= byte && byte < 256)
      return byte
    sufV4 = ["arpa","in-addr"]

-- | parse IPv6 4bit-parts from reverse-lookup domain
--
-- >>> parseV6RevDomain "a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa"
-- Right [2,0,0,1,0,13,11,8,0,15,0,0,0,0,0,0,0,0,1,2,3,4,15,15,15,14,5,6,7,8,9,10]
parseV6RevDomain :: Domain -> Either String [Int]
parseV6RevDomain dom = do
  rparts <- maybe (throw "suffix does not match") Right $ L.stripPrefix sufV6 $ reverse $ DNS.toWireLabels dom
  let plen = length rparts
  maybe (throw $ "invalid number of parts split by dot: " ++ show rparts) Right
    $ guard (1 <= plen && plen <= 32)
  mapM getHexDigit rparts
  where
    throw = Left . ("v6Rev: " ++)
    getHexDigit s = do
      h <- case [ x | (x, "")  <- readHex $ B8.unpack (Short.fromShort s) ] of
             []    ->  throw $ "cannot parse hexadecimal from part: " ++ show s
             [x]   ->  Right x
             _:_   ->  throw $ "ambiguous parse result of hexadecimal part: " ++ show s
      maybe (throw $ "hexadecimal part '" ++ showHex h "" ++ "' is out of range") Right
        $ guard (0 <= h && h < 0x10)
      return h
    sufV6 = ["arpa", "ip6"]

-- show IPv4 reverse-lookup domain from 8bit-parts
showV4RevDomain :: [Int] -> Domain
showV4RevDomain parts = DNS.fromRepresentation $ intercalate "." (map show $ reverse parts) ++ ".in-addr.arpa."

-- parse IPv6 reverse-lookup domain from 4bit-parts
showV6RevDomain :: [Int] -> Domain
showV6RevDomain parts = DNS.fromRepresentation $ intercalate "." (map (`showHex` "") $ reverse parts) ++ ".ip6.arpa."

-- make IPv4-address and mask-length from prefix 8bit-parts
withMaskLenV4 :: [Int] -> (IPv4, Int)
withMaskLenV4 bs = (toIPv4 $ take 4 $ bs ++ pad, length bs * 8)
  where pad = replicate (4-1) 0

-- make IPv6-address and mask-length from prefix 4bit-parts
withMaskLenV6 :: [Int] -> (IPv6, Int)
withMaskLenV6 hs = (toIPv6h $ take 32 $ hs ++ pad, length hs * 4)
  where
    pad = replicate (32-1) 0
    toIPv6h = toIPv6b . bytes
    bytes []        =  []
    bytes [h]       =  [h `shiftL` 4]
    bytes (h:l:xs)  =  ((h `shiftL` 4) .|. l) : bytes xs

-- result output tags for special IP-blocks
data EmbedResult
  = EmbedLocal
  | EmbedInAddr
  | EmbedIp6
  deriving Show

{- IPv4 Special-Purpose Address Registry Entries
   https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.2 -}
specialV4Blocks :: [(Int, IPv4, Map IPv4 EmbedResult)]
specialV4Blocks =
  map groupMap $
  groupBy ((==) `on` IP.mlen . fst) $ sortOn (IP.mlen . fst) $
  map (first read)
  [ ("0.0.0.0/8"          , EmbedLocal ) {- This host on this network  -}
  , ("10.0.0.0/8"         , EmbedInAddr) {- Private-Use                -}
  , ("100.64.0.0/10"      , EmbedInAddr) {- Shared Address Space       -}
  , ("127.0.0.0/8"        , EmbedLocal ) {- Loopback                   -}
  , ("169.254.0.0/16"     , EmbedInAddr) {- Link Local                 -}
  , ("172.16.0.0/12"      , EmbedInAddr) {- Private-Use                -}
  -- ("192.0.0.0/24"       , _          ) {- IETF Protocol Assignments  -} {- not handled in resolvers -}
  -- ("192.0.0.0/29"       , _          ) {- DS-Lite                    -} {- not handled in resolvers -}
  , ("192.0.2.0/24"       , EmbedInAddr) {- Documentation (TEST-NET-1) -}
  -- ("192.88.99.0/24"     , _          ) {- 6to4 Relay Anycast         -} {- not handled in resolvers -}
  , ("192.168.0.0/16"     , EmbedInAddr) {- Private-Use                -}
  -- ("198.18.0.0/15"      , _          ) {- Benchmarking               -} {- not handled in resolvers -}
  , ("198.51.100.0/24"    , EmbedInAddr) {- Documentation (TEST-NET-2) -}
  , ("203.0.113.0/24"     , EmbedInAddr) {- Documentation (TEST-NET-3) -}
  -- ("240.0.0.0/4"        , _          ) {- Reserved                   -} {- not handled in resolvers -}
  , ("255.255.255.255/32" , EmbedInAddr) {- Limited Broadcast          -}
  ]
  where
    groupMap rs = (IP.mlen r, IP.mask r, Map.fromList [ (IP.addr range, res) | (range, res) <- rs ])
      where r = fst $ head rs

{- IPv6 Special-Purpose Address Registry Entries
   https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.3 -}
specialV6Blocks :: [(Int, IPv6, Map IPv6 EmbedResult)]
specialV6Blocks =
  map groupMap $
  groupBy ((==) `on` IP.mlen . fst) $ sortOn (IP.mlen . fst) $
  map (first read)
  [ ("::1/128"            , EmbedIp6   ) {- Loopback Address           -}
  , ("::/128"             , EmbedIp6   ) {- Unspecified Address        -}
  -- ("64:ff9b::/96"       , _          ) {- IPv4-IPv6 Translat.        -} {- not handled in resolvers -}
  -- ("::ffff:0.0.0.0/96"  , _          ) {- IPv4-mapped Address        -} {- not handled in resolvers -}
  -- ("100::/64"           , _          ) {- Discard-Only Address Block -} {- not handled in resolvers -}
  -- ("2001::/23"          , _          ) {- IETF Protocol Assignments  -} {- not handled in resolvers -}
  -- ("2001::/32"          , _          ) {- TEREDO                     -} {- not handled in resolvers -}
  -- ("2001:2::/48"        , _          ) {- Benchmarking               -} {- not handled in resolvers -}
  , ("2001:db8::/32"      , EmbedIp6   ) {- Documentation              -}
  -- ("2001:10::/28"       , _          ) {- ORCHID                     -} {- not handled in resolvers -}
  -- ("2002::/16"          , _          ) {- 6to4                       -} {- not handled in resolvers -}
  -- ("fc00::/7"           , _          ) {- Unique-Local               -} {- not handled in resolvers -}
  , ("fe80::/10"          , EmbedIp6   ) {- Linked-Scoped Unicast      -}
  ]
  where
    groupMap rs = (IP.mlen r, IP.mask r, Map.fromList [ (IP.addr range, res) | (range, res) <- rs ])
      where r = fst $ head rs

runEmbedResult :: Domain -> EmbedResult -> Result
runEmbedResult dom emb = (DNS.NameErr, [], [soa emb])
  where
    soa EmbedLocal   = soaRR "localhost." "root@localhost." 1 604800 86400 2419200 604800
    soa EmbedInAddr  = soaRR dom "." 0 28800 7200 604800 86400
    soa EmbedIp6     = soaRR dom "." 0 28800 7200 604800 86400
    soaRR mname mail ser refresh retry expire ncttl =
      ResourceRecord { rrname = dom, rrtype = SOA, rrclass = classIN, rrttl = ncttl
                     , rdata = DNS.rd_soa mname mail ser refresh retry expire ncttl }

-- detect embedded result for special IP-address block from reverse lookup domain
takeEmbeddedResult :: (Ord a, IP.Addr a)
                   => (Domain -> Either String [Int])
                   -> ([Int] -> Domain)
                   -> ([Int] -> (a, Int))
                   -> [(Int, a, Map a EmbedResult)]
                   -> Int
                   -> Domain
                   -> Maybe ((Domain, EmbedResult), IP.AddrRange a)
takeEmbeddedResult parse show_ withMaskLen blocks partWidth dom = do
  parts <- either (const Nothing) Just $ parse dom
  let (ip, len) = withMaskLen parts
  listToMaybe
    [ ((show_ $ take maskedPartsLen parts, result), IP.makeAddrRange prefix mlen)
    | (mlen, mask, pairs) <- blocks
    , len >= mlen
    , let prefix = IP.masked ip mask
    , Just result <- [Map.lookup prefix pairs]
    , let maskedPartsLen = ceiling (fromIntegral mlen / fromIntegral partWidth :: Rational)
    ]

v4EmbeddedResult :: Domain -> Maybe ((Domain, EmbedResult), IP.AddrRange IPv4)
v4EmbeddedResult = takeEmbeddedResult parseV4RevDomain showV4RevDomain withMaskLenV4 specialV4Blocks 8

v6EmbeddedResult :: Domain -> Maybe ((Domain, EmbedResult), IP.AddrRange IPv6)
v6EmbeddedResult = takeEmbeddedResult parseV6RevDomain showV6RevDomain withMaskLenV6 specialV6Blocks 4

-- result for special IP-address block from reverse lookup domain
takeSpecialRevDomainResult :: Domain -> Maybe Result
takeSpecialRevDomainResult dom = fmap (uncurry runEmbedResult) $ fst <$> v4EmbeddedResult dom <|> fst <$> v6EmbeddedResult dom

-----

guardRequestHeader :: DNSHeader -> DNSQuery ()
guardRequestHeader reqH = unless rd $ throwE $ HasError DNS.Refused DNS.defaultResponse
  where
    rd = DNS.recDesired $ DNS.flags reqH

replyMessage :: Either QueryError Result
             -> DNS.Identifier -> [DNS.Question]
             -> Either String DNSMessage
replyMessage eas ident rqs =
  either queryError (Right . message) eas
  where
    dnsError de = fmap message $ (,,) <$> rcodeDNSError de <*> pure [] <*> pure []
    rcodeDNSError e = case e of
      DNS.RetryLimitExceeded  ->  Right DNS.ServFail
      DNS.FormatError         ->  Right DNS.FormatErr
      DNS.ServerFailure       ->  Right DNS.ServFail
      DNS.NotImplemented      ->  Right DNS.NotImpl
      DNS.OperationRefused    ->  Right DNS.ServFail {- like bind9 behavior -}
      DNS.BadOptRecord        ->  Right DNS.BadVers
      _                       ->  Left $ "DNSError: " ++ show e

    queryError qe = case qe of
      DnsError e      ->  dnsError e
      NotResponse {}  ->  Left "qORr is not response"
      InvalidEDNS {}  ->  Left "Invalid EDNS"
      HasError rc _m  ->  Right $ message (rrc, [], [])
        where rrc = case rc of
                DNS.Refused  ->  DNS.ServFail
                _            ->  rc

    message (rcode, rrs, auth) =
      res
      { DNS.header = h { DNS.identifier = ident
                       , DNS.flags = f { DNS.authAnswer = False, DNS.rcode = rcode } }
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
  ((aRRs, _rn), etm) <- resolve n typ
  let fromMessage msg = (DNS.rcode $ DNS.flags $ DNS.header msg, DNS.answer msg, allowAuthority $ DNS.authority msg)
      makeResult (rcode, ans, auth) = (rcode, aRRs ans, auth)
  return $ makeResult $ either id fromMessage etm
    where
      allowAuthority = foldr takeSOA []
      takeSOA rr@ResourceRecord { rrtype = SOA } xs  =  rr : xs
      takeSOA _                                  xs  =  xs

replyResultCached :: Domain -> TYPE -> DNSQuery (Maybe Result)
replyResultCached n typ = do
  ((aRRs, _rn), e) <- resolveByCache n typ
  let makeResult (rcode, ans, auth) = (rcode, aRRs ans, auth)
  return $ either (Just . makeResult) (const Nothing) e

maxCNameChain :: Int
maxCNameChain = 16

type DRRList = [ResourceRecord] -> [ResourceRecord]

resolveByCache :: Domain -> TYPE -> DNSQuery ((DRRList, Domain), Either Result ())
resolveByCache = resolveLogic "cache" (\_ -> pure ()) (\_ _ -> pure ((), Nothing))

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードをキャッシュする. -}
resolve :: Domain -> TYPE -> DNSQuery ((DRRList, Domain), Either Result DNSMessage)
resolve = resolveLogic "query" resolveCNAME resolveTYPE

resolveLogic :: String
             -> (Domain -> DNSQuery a)
             -> (Domain -> TYPE -> DNSQuery (a, Maybe (Domain, ResourceRecord)))
             -> Domain -> TYPE -> DNSQuery ((DRRList, Domain), Either Result a)
resolveLogic logMark cnameHandler typeHandler n0 typ =
  maybe notSpecial special $ takeSpecialRevDomainResult n0
  where
    special result = return ((id, n0), Left result)
    notSpecial
      | typ == CNAME  =  called *> justCNAME n0
      | otherwise     =  called *> recCNAMEs 0 n0 id
    called = lift $ logLn Log.DEBUG $ "resolve: " ++ logMark ++ ": " ++ show (n0, typ)
    justCNAME bn = do
      let noCache = do
            msg <- cnameHandler bn
            pure ((id, bn), Right msg)

          withNXC (soa, _rank) = pure ((id, bn), Left (DNS.NameErr, [], soa))

          cachedCNAME (rrs, soa) = pure ((id, bn), Left (DNS.NoErr, rrs, soa))  {- target RR is not CNAME destination but CNAME, so NoErr -}

      maybe
        (maybe noCache withNXC =<< lift (lookupNX bn))
        (cachedCNAME . either (\soa -> ([], soa)) (\(_cn, cnRR) -> ([cnRR], [])))
        =<< lift (lookupCNAME bn)

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    -- recCNAMEs :: Int -> Domain -> DRRList -> DNSQuery ((DRRList, Domain), Either Result a)
    recCNAMEs cc bn aRRs
      | cc > mcc  = lift (logLn Log.NOTICE $ "query: cname chain limit exceeded: " ++ show (n0, typ))
                    *> throwDnsError DNS.ServerFailure
      | otherwise = do
      let recCNAMEs_ (cn, cnRR) = recCNAMEs (succ cc) cn (aRRs . (cnRR :))
          noCache = do
            (msg, cname) <- typeHandler bn typ
            maybe (pure ((aRRs, bn), Right msg)) recCNAMEs_ cname

          withNXC (soa, _rank) = pure ((aRRs, bn), Left (DNS.NameErr, [], soa))

          noTypeCache =
            maybe
            (maybe noCache withNXC =<< lift (lookupNX bn))
            recCNAMEs_ {- recurse with cname cache -}
            =<< lift (joinE <$> lookupCNAME bn)  {- CNAME が NODATA だったときは CNAME による再検索をしないケースとして扱う -}
            where joinE = (either (const Nothing) Just =<<)

          cachedType (tyRRs, soa) = pure ((aRRs, bn), Left (DNS.NoErr, tyRRs, soa))

      maybe
        noTypeCache
        (cachedType . either (\(soa, _rank) -> ([], soa)) (\tyRRs -> (tyRRs, []))) {- return cached result with target typ -}
        =<< lift (lookupType bn typ)

        where
          mcc = maxCNameChain

    lookupNX :: Domain -> ContextT IO (Maybe ([ResourceRecord], Ranking))
    lookupNX bn = maybe (return Nothing) (either (return . Just) inconsistent) =<< lookupType bn Cache.nxTYPE
      where inconsistent rrs = do
              logLn Log.NOTICE $ "resolve: inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
              return Nothing

    -- Nothing のときはキャッシュに無し
    -- Just Left のときはキャッシュに有るが CNAME レコード無し
    lookupCNAME :: Domain -> ContextT IO (Maybe (Either [ResourceRecord] (Domain, ResourceRecord)))
    lookupCNAME bn = do
      maySOAorCNRRs <- lookupType bn CNAME
      return $ do
        let soa (rrs, _rank) = Just $ Left rrs
            cname rrs = Right . fst <$> uncons (cnameList bn (,) rrs)  {- empty ではないはずなのに cname が空のときはキャッシュ無しとする -}
        either soa cname =<< maySOAorCNRRs

    lookupType bn t = (replyRank =<<) <$> lookupCacheEither logMark bn t
    replyRank (x, rank)
      -- 最も低い ranking は reply の answer に利用しない
      -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
      | rank <= RankAdditional  =  Nothing
      | otherwise               =  Just x

{- CNAME のレコードを取得し、キャッシュする -}
resolveCNAME :: Domain -> DNSQuery DNSMessage
resolveCNAME bn = do
  (msg, _nss@(srcDom, _, _, _)) <- resolveJust bn CNAME
  lift $ cacheAnswer srcDom bn CNAME msg
  return msg

{- 目的の TYPE のレコードの取得を試み、結果の DNSMessage を返す.
   結果が CNAME なら、その RR も返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
resolveTYPE :: Domain -> TYPE
            -> DNSQuery (DNSMessage, Maybe (Domain, ResourceRecord))  {- result msg and cname RR involved in -}
resolveTYPE bn typ = do
  (msg, _nss@(srcDom, _, _, _)) <- resolveJust bn typ
  cname <- lift $ getSectionWithCache rankedAnswer refinesCNAME msg
  let checkTypeRR =
        when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
          throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
  maybe (lift $ cacheAnswer srcDom bn typ msg) (const checkTypeRR) cname
  return (msg, cname)
    where
      refinesCNAME rrs = (fst <$> uncons ps, map snd ps)
        where ps = cnameList bn (,) rrs

cacheAnswer :: Domain -> Domain -> TYPE -> DNSMessage -> ContextT IO ()
cacheAnswer srcDom dom typ msg
  | null $ DNS.answer msg  =  do
      case rcode of
        DNS.NoErr    ->  cacheEmptySection srcDom dom typ rankedAnswer msg
        DNS.NameErr  ->  cacheEmptySection srcDom dom Cache.nxTYPE rankedAnswer msg
        _            ->  return ()
  | otherwise              =  do
      getSectionWithCache rankedAnswer refinesX msg
  where
    rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    refinesX rrs = ((), ps)
      where
        ps = filter isX rrs
        isX rr = rrname rr == dom && rrtype rr == typ

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveJust :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveJustDC 0

resolveJustDC :: Int -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJustDC dc n typ
  | dc > mdc   = lift (logLn Log.NOTICE $ "resolve-just: not sub-level delegation limit exceeded: " ++ show (n, typ))
                 *> throwDnsError DNS.ServerFailure
  | otherwise  = do
  lift $ logLn Log.INFO $ "resolve-just: " ++ "dc=" ++ show dc ++ ", " ++ show (n, typ)
  nss <- iterative_ dc rootNS $ reverse $ DNS.superDomains n
  sas <- delegationIPs dc nss
  lift $ logLines Log.INFO $ [ "resolve-just: selected addrs: " ++ show (sa, n, typ) | sa <- sas ]
  (,) <$> norec False sas n typ <*> pure nss
    where
      mdc = maxNotSublevelDelegation

{- delegation information for domain -}
type Delegation =
  (Domain,      {- destination domain -}
   NE DEntry,   {- NS infos of destination, get from source NS -}
   [RD_DS],     {- signature of destination SEP DNSKEY, get from source NS -}
   [RD_DNSKEY]  {- destination DNSKEY set, get from destination NS -})

data DEntry
  = DEwithAx !Domain !IP
  | DEonlyNS !Domain
  deriving Show

nsDomain :: DEntry -> Domain
nsDomain (DEwithAx dom _)  =  dom
nsDomain (DEonlyNS dom  )  =  dom

v4DEntryList :: [DEntry] -> [DEntry]
v4DEntryList []          =  []
v4DEntryList des@(de:_)  =  concatMap skipAAAA $ byNS des
  where
    byNS = groupBy ((==) `on` nsDomain)
    skipAAAA = nullCase . filter (not . aaaaDE)
      where
        aaaaDE (DEwithAx _ (IPv6 {})) = True
        aaaaDE _                      = False
        nullCase     []    =  [DEonlyNS (nsDomain de)]
        nullCase es@(_:_)  =  es

rootNS :: Delegation
rootNS = rootHint

-- {-# ANN rootHint ("HLint: ignore Use tuple-section") #-}
rootHint :: Delegation
rootHint =
  fromMaybe
  (error "rootHint: bad configuration.")
  $ takeDelegationSrc (nsList "." (,) ns) [] as
  where
    (ns, as) = rootServers

data MayDelegation
  = NoDelegation  {- no delegation information -}
  | HasDelegation Delegation

mayDelegation :: a -> (Delegation -> a) -> MayDelegation -> a
mayDelegation n h md = case md of
  NoDelegation     ->  n
  HasDelegation d  ->  h d

-- 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
iterative :: Delegation -> Domain -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ reverse $ DNS.superDomains n

iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery Delegation
iterative_ _  nss []     = return nss
iterative_ dc nss (x:xs) =
  step nss >>=
  mayDelegation
  (recurse nss xs)   -- NS が返らない場合は同じ NS の情報で子ドメインへ. 通常のホスト名もこのケース. ex. or.jp, ad.jp
  (`recurse` xs)
  where
    recurse = iterative_ dc  {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    lookupNX :: ContextT IO Bool
    lookupNX = isJust <$> lookupCache name Cache.nxTYPE

    stepQuery :: Delegation -> DNSQuery MayDelegation
    stepQuery nss_@(srcDom, _, _, _) = do
      sas <- delegationIPs dc nss_ {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
      lift $ logLines Log.INFO $ [ "iterative: selected addrs: " ++ show (sa, name, A) | sa <- sas ]
      {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
         See the following document:
         QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
      msg <- norec False sas name A
      lift $ delegationWithCache srcDom name msg

    step :: Delegation -> DNSQuery MayDelegation
    step nss_ = do
      let withNXC nxc
            | nxc        =  return NoDelegation
            | otherwise  =  stepQuery nss_
      maybe (withNXC =<< lift lookupNX) return =<< lift (lookupDelegation name)

-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation dom = do
  disableV6NS <- asks disableV6NS_
  let lookupDEs ns = do
        let deListA    = rrListWith A    (`DNS.rdataField` DNS.a_ipv4)    ns (\v4 _ -> DEwithAx ns (IPv4 v4))
            deListAAAA = rrListWith AAAA (`DNS.rdataField` DNS.aaaa_ipv6) ns (\v6 _ -> DEwithAx ns (IPv6 v6))

        lk4 <- fmap (deListA . fst)    <$> lookupCache ns A
        lk6 <- fmap (deListAAAA . fst) <$> lookupCache ns AAAA
        return $ case lk4 <> lk6 of
          Nothing
            | ns `DNS.isSubDomainOf` dom  ->  []             {- miss-hit with sub-domain case cause iterative loop, so return null to skip this NS -}
            | otherwise               ->  [DEonlyNS ns]  {- the case both A and AAAA are miss-hit -}
          Just as                     ->  as             {- just return address records. null case is wrong cache, so return null to skip this NS -}
      noCachedV4NS es = disableV6NS && null (v4DEntryList es)
      fromDEs es
        | noCachedV4NS es  =  Nothing
        {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
        | otherwise        =  (\des -> HasDelegation $ (dom, des, [], [])) <$> uncons es
        {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
      getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
      getDelegation (rrs, _) = do {- NS cache hit -}
        let nss = sort $ nsList dom const rrs
        case nss of
          []    ->  return $ Just NoDelegation  {- hit null NS list, so no delegation -}
          _:_   ->  fromDEs . concat <$> mapM lookupDEs nss

  maybe (return Nothing) getDelegation =<< lookupCache dom NS

-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache :: Domain -> Domain -> DNSMessage -> ContextT IO MayDelegation
delegationWithCache srcDom dom msg =
  -- There is delegation information only when there is a selectable NS
  maybe
  (ncache $> NoDelegation)
  (fmap HasDelegation . withCache)
  $ takeDelegationSrc nsps dss adds
  where
    withCache x = do
      {- TODO: check DS with RRSIG, and cache DS with RRSIG -}
      cacheNS
      cacheAdds
      return x

    (authRRs, authorityRank) = rankedAuthority msg
    dss = rrListWith DS DNS.fromRData dom const authRRs
    _sigrds :: [RD_RRSIG]
    _sigrds = rrListWith RRSIG DNS.fromRData dom const authRRs
    cacheNS = cacheSection nsRRs authorityRank
    (nsps, nsRRs) = unzip $ nsList dom (\ns rr -> ((ns, rr), rr)) authRRs

    (adds, cacheAdds) = getSection rankedAdditional refinesAofNS msg
      where refinesAofNS rrs = (rrs, sortOn (rrname &&& rrtype) $ filter match rrs)
            match rr = rrtype rr `elem` [A, AAAA] && rrname rr `Set.member` nsSet
            nsSet = Set.fromList $ map fst nsps

    ncache
      | rcode == DNS.NoErr    =  cacheEmptySection srcDom dom NS rankedAuthority msg
      | rcode == DNS.NameErr  =
        if hasCNAME then      do cacheCNAME
                                 cacheEmptySection srcDom dom NS rankedAuthority msg
        else                     cacheEmptySection srcDom dom Cache.nxTYPE rankedAuthority msg
      | otherwise             =  pure ()
      where rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    (hasCNAME, cacheCNAME) = getSection rankedAnswer refinesCNAME msg
      where refinesCNAME rrs = (not $ null cns, crrs)
            {- CNAME 先の NX をキャッシュしたいならここで返す.
               しかしCNAME 先の NS に問い合わせないと返答で使える rank のレコードは得られない. -}
              where (cns, crrs) = unzip $ cnameList dom (,) rrs

takeDelegationSrc :: [(Domain, ResourceRecord)]
                  -> [RD_DS]
                  -> [ResourceRecord]
                  -> Maybe Delegation
takeDelegationSrc nsps dss adds = do
  (p@(_, rr), ps) <- uncons nsps
  let nss = map fst (p:ps)
  ents <- uncons $ concatMap (uncurry dentries) $ rrnamePairs (sort nss) addgroups
  {- only data from delegation source zone. get DNSKEY from destination zone -}
  return (rrname rr, ents, dss, [])
  where
    addgroups = groupBy ((==) `on` rrname) $ sortOn ((,) <$> rrname <*> rrtype) adds
    dentries d     []     =  [DEonlyNS d]
    dentries d as@(_:_)
      | null axs          =  [DEonlyNS d]
      | otherwise         =  axs
      where axs = axList False (const True {- paired by rrnamePairs -}) (\ip _ -> DEwithAx d ip) as

-- | pairing correspond rrname domain data
--
-- >>> let agroup n = [ ResourceRecord { rrname = n, rrtype = A, rrclass = classIN, rrttl = 60, rdata = DNS.rd_a a } | a <- ["10.0.0.1", "10.0.0.2"] ]
-- >>> rrnamePairs ["s", "t", "u"] [agroup "s", agroup "t", agroup "u"] == [("s", agroup "s"), ("t", agroup "t"), ("u", agroup "u")]
-- True
-- >>> rrnamePairs ["t"] [agroup "s", agroup "t", agroup "u"] == [("t", agroup "t")]
-- True
-- >>> rrnamePairs ["s", "t", "u"] [agroup "t"] == [("s", []), ("t", agroup "t"), ("u", [])]
-- True
rrnamePairs :: [Domain] -> [[ResourceRecord]] -> [(Domain, [ResourceRecord])]
rrnamePairs []     _gs        =  []
rrnamePairs (d:ds)  []        =  (d, []) : rrnamePairs ds  []
rrnamePairs dds@(d:ds) ggs@(g:gs)
  | d <  an                   =  (d, []) : rrnamePairs ds  ggs
  | d == an                   =  (d, g)  : rrnamePairs ds  gs
  | otherwise {- d >  an  -}  =            rrnamePairs dds gs  -- unknown additional RRs. just skip
  where
    an = rrname a
    a = head g

---

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. validate SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY :: [RD_DS] -> [IP] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY dss aservers dom = do
  eresult <- verifiedDNSKEY dss aservers dom
  let doCache (dnskeys, rrsigs, rank) = do
        let keyRRs = map snd dnskeys
            sigRRs = map snd rrsigs
        withMinTTL (keyRRs ++ sigRRs) (return $ Left $ "cachedDNSKEY: empty DNSKEY list - something wrong") $ \minTTL -> do
          cacheSection (withTTL minTTL keyRRs) rank {- TODO: cache with RRSIG of DNSKEY -}
          return $ Right $ map fst dnskeys
  either (return . Left) (lift . doCache) eresult

verifiedDNSKEY :: [RD_DS] -> [IP] -> Domain -> DNSQuery (Either String ([(RD_DNSKEY, ResourceRecord)], [(RD_RRSIG, ResourceRecord)], Ranking))
verifiedDNSKEY dss aservers dom
  | null dss   =  return $ Left $ verifyError "no DS entry"
  | otherwise  =  do
      msg <- norec True aservers dom DNSKEY

      return $ do
        let (answer, answerRank) = rankedAnswer msg
            rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        unless (rcode == DNS.NoErr) $ Left $ verifyError $ "error rcode to get DNSKEY: " ++ show rcode

        let rrsigs = rrListWith RRSIG DNS.fromRData dom (,) answer
        when (null rrsigs) $ Left $ verifyError "no RRSIG found for DNSKEY"

        let dnskeys = rrListWith DNSKEY DNS.fromRData dom (,) answer
            seps =
              [ (key, ds)
              | (key, _) <- dnskeys
              , ds  <- dss
              , Right () <- [SEC.verifyDS dom key ds]
              ]
        when (null seps) $ Left $ verifyError "no DNSKEY matches with DS"

        let keyRRs = map snd dnskeys
            goodSigs =
              [ rrsig
              | rrsig@(sigrd, _) <- rrsigs
              , (sepkey, _) <- seps
              , Right () <- [SEC.verifyRRSIG sepkey sigrd keyRRs]
              ]
        when (null goodSigs) $ Left $ verifyError "no verified RRSIG found"

        return (dnskeys, goodSigs, answerRank)
      where
        verifyError s = "verifiedDNSKEY: " ++ s

---

withMinTTL :: [ResourceRecord] -> a -> (TTL -> a) -> a
withMinTTL rrs failed action =
  maybe failed action
  $ uncons rrs *> Just (minimum [ rrttl x | x <- rrs ])

withTTL :: TTL -> [ResourceRecord] -> [ResourceRecord]
withTTL ttl rrs = map update rrs
  where
    update rr
      | ttl < rrttl rr  =  rr { rrttl = ttl }
      | otherwise       =  rr

nsList :: Domain -> (Domain ->  ResourceRecord -> a)
       -> [ResourceRecord] -> [a]
nsList = rrListWith NS $ \rd -> DNS.rdataField rd DNS.ns_domain

cnameList :: Domain -> (Domain -> ResourceRecord -> a)
          -> [ResourceRecord] -> [a]
cnameList = rrListWith CNAME $ \rd -> DNS.rdataField rd DNS.cname_domain

rrListWith :: TYPE -> (DNS.RData -> Maybe rd)
           -> Domain -> (rd -> ResourceRecord -> a)
           -> [ResourceRecord] -> [a]
rrListWith typ fromRD dom h = foldr takeRR []
  where
    takeRR rr@ResourceRecord { rdata = rd } xs
      | rrname rr == dom, rrtype rr == typ, Just ds <- fromRD rd  =  h ds rr : xs
    takeRR _                                xs                    =  xs

axList :: Bool
       -> (Domain -> Bool) -> (IP -> ResourceRecord -> a)
       -> [ResourceRecord] -> [a]
axList disableV6NS pdom h = foldr takeAx []
  where
    takeAx rr@ResourceRecord { rrtype = A, rdata = rd } xs
      | pdom (rrname rr),
        Just v4 <- DNS.rdataField rd DNS.a_ipv4    = h (IPv4 v4) rr : xs
    takeAx rr@ResourceRecord { rrtype = AAAA, rdata = rd } xs
      | not disableV6NS && pdom (rrname rr),
        Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 = h (IPv6 v6) rr : xs
    takeAx _         xs  =  xs

---

-- 権威サーバーから答えの DNSMessage を得る. 再起検索フラグを落として問い合わせる.
norec :: Bool -> [IP] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnsssecOK aservers name typ = dnsQueryT $ \cxt -> do
  let ris =
        [ defaultResolvInfo {
            rinfoHostName   = show aserver
          , rinfoActions    = defaultResolvActions {
              ractionGenId   = idGen_ cxt
            , ractionGetTime = currentSeconds_ cxt
            }
          }
        | aserver <- aservers
        ]
      renv = ResolvEnv {
          renvResolver    = udpTcpResolver 3 (32 * 1024) -- 3 is retry
        , renvConcurrent  = True -- should set True if multiple RIs are provided
        , renvResolvInfos = ris
        }
      q = Question name typ classIN
      doFlagSet
        | dnsssecOK  =  FlagSet
        | otherwise  =  FlagClear
      qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
  either (Left . DnsError) (\res -> handleResponseError Left Right $ DNS.replyDNSMessage (DNS.resultReply res)) <$>
    E.try (DNS.resolve renv q qctl)

-- Filter authoritative server addresses from the delegation information.
-- If the resolution result is NODATA, IllegalDomain is returned.
delegationIPs :: Int -> Delegation -> DNSQuery [IP]
delegationIPs dc (srcDom, des, _, _) = do
  lift $ logLn Log.INFO $ ppDelegation des
  disableV6NS <- lift $ asks disableV6NS_

  let takeDEntryIP (DEonlyNS {})             xs  =  xs
      takeDEntryIP (DEwithAx _ ip@(IPv4 {})) xs  =  ip : xs
      takeDEntryIP (DEwithAx _ ip@(IPv6 {})) xs
        | disableV6NS                            =  xs
        | otherwise                              =  ip : xs
      ips = foldr takeDEntryIP [] (fst des : snd des)

      takeNames (DEonlyNS name) xs = name : xs
      takeNames _               xs = xs

      names = foldr takeNames [] (fst des : snd des)

      result
        | not (null ips)    =  return ips
        | not (null names)  =  do
            mayName <- liftIO $ randomizedSelect names
            let neverReach = do
                  lift $ logLn Log.INFO $ "delegationIPs: never reach this action."
                  throwDnsError DNS.ServerFailure
            maybe neverReach (fmap ((:[]) . fst) . resolveNS disableV6NS dc) mayName
        | disableV6NS       =  do
            lift $ logLn Log.INFO $ "delegationIPs: server-fail: domain: " ++ show srcDom ++ ", delegation is empty."
            throwDnsError DNS.ServerFailure
        | otherwise         = do
            lift $ logLn Log.INFO $ "delegationIPs: illegal-domain: " ++ show srcDom ++ ", delegation is empty."
            throwDnsError DNS.IllegalDomain

  result

resolveNS :: Bool -> Int -> Domain -> DNSQuery (IP, ResourceRecord)
resolveNS disableV6NS dc ns = do
  let axPairs = axList disableV6NS (== ns) (,)

      refinesAx rrs = (ps, map snd ps)
        where ps = axPairs rrs

      lookupAx
        | disableV6NS  =  lk4
        | otherwise    =  join $ liftIO $ randomizedSelectN (lk46, [lk64])
        where
          lk46 = lk4 +? lk6
          lk64 = lk6 +? lk4
          lk4 = lookupCache ns A
          lk6 = lookupCache ns AAAA
          lx +? ly = maybe ly (return . Just) =<< lx

      query1Ax
        | disableV6NS  =  q4
        | otherwise    =  join $ liftIO $ randomizedSelectN (q46, [q64])
        where
          q46 = q4 +!? q6 ; q64 = q6 +!? q4
          q4 = querySection A
          q6 = querySection AAAA
          qx +!? qy = do
            xs <- qx
            if null xs then qy else pure xs
          querySection typ = lift . getSectionWithCache rankedAnswer refinesAx . fst
                             =<< resolveJustDC (succ dc) ns typ {- resolve for not sub-level delegation. increase dc (delegation count) -}

      resolveAXofNS :: DNSQuery (IP, ResourceRecord)
      resolveAXofNS = do
        let selectA = randomizedSelect
            failEmptyAx
              | disableV6NS = do
                  lift $ logLn Log.NOTICE $ "resolveNS: server-fail: NS: " ++ show ns ++ ", address is empty."
                  throwDnsError DNS.ServerFailure
              | otherwise   = do
                  lift $ logLn Log.NOTICE $ "resolveNS: illegal-domain: NS: " ++ show ns ++ ", address is empty."
                  throwDnsError DNS.IllegalDomain
        maybe failEmptyAx pure =<< liftIO . selectA  {- 失敗時: NS に対応する A の返答が空 -}
          =<< maybe query1Ax (pure . axPairs . fst) =<< lift lookupAx

  resolveAXofNS

randomSelect :: Bool
randomSelect = True

randomizedSelectN :: NE a -> IO a
randomizedSelectN
  | randomSelect  =  d
  | otherwise     =  return . fst  -- naive implementation
  where
    d (x, []) = return x
    d (x, xs) = do
      ix <- getStdRandom $ randomR (0, length xs)
      return $ (x:xs) !! ix

randomizedSelect :: [a] -> IO (Maybe a)
randomizedSelect
  | randomSelect  =  d
  | otherwise     =  return . listToMaybe  -- naive implementation
  where
    d []   =  return Nothing
    d [x]  =  return $ Just x
    d xs   =  do
      ix <- getStdRandom $ randomR (0, length xs - 1)
      return $ Just $ xs !! ix

---

lookupCache :: Domain -> TYPE -> ContextT IO (Maybe ([ResourceRecord], Ranking))
lookupCache dom typ = do
  getCache <- asks getCache_
  getSec <- asks currentSeconds_
  result <- liftIO $ do
    cache <- getCache
    ts <- getSec
    return $ Cache.lookup ts dom typ DNS.classIN cache
  logLn Log.DEBUG $ "lookupCache: " ++ unwords [show dom, show typ, show DNS.classIN, ":",
                                        maybe "miss" (\ (_, rank) -> "hit: " ++ show rank) result]
  return result

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupCacheEither :: String -> Domain -> TYPE
                  -> ContextT IO (Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking))
lookupCacheEither logMark dom typ = do
  getCache <- asks getCache_
  getSec <- asks currentSeconds_
  result <- liftIO $ do
    cache <- getCache
    ts <- getSec
    return $ Cache.lookupEither ts dom typ DNS.classIN cache
  logLn Log.DEBUG $
   "lookupCacheEither: " ++ logMark ++ ": " ++
    unwords [show dom, show typ, show DNS.classIN, ":", maybe "miss" (\ (_, rank) -> "hit: " ++ show rank) result]
  return result

getSection :: (m -> ([ResourceRecord], Ranking))
           -> ([ResourceRecord] -> (a, [ResourceRecord]))
           -> m -> (a, ContextT IO ())
getSection getRanked refines msg =
  withSection $ getRanked msg
  where
    withSection (rrs0, rank) = (result, cacheSection srrs rank)
      where (result, srrs) = refines rrs0

getSectionWithCache :: (m -> ([ResourceRecord], Ranking))
                    -> ([ResourceRecord] -> (a, [ResourceRecord]))
                    -> m -> ContextT IO a
getSectionWithCache get refines msg = do
  let (res, doCache) = getSection get refines msg
  doCache
  return res

cacheSection :: [ResourceRecord] -> Ranking -> ContextT IO ()
cacheSection rs rank = cacheRRSet
  where
    (ncRRSs, rrss) = insertSetFromSection rs rank
    putRRSet putk = putk $ \key ttl crs r ->
      logLines Log.DEBUG
      [ "cacheRRSet: " ++ show ((key, ttl), r)
      , "  " ++ show crs ]
    putNoCacheRRS rrs =
      logLines Log.NOTICE $
      "cacheSection: no caching RR set:" :
      map (("  " ++) . show) rrs
    cacheRRSet = do
      mapM_ putNoCacheRRS ncRRSs
      mapM_ putRRSet rrss
      insertRRSet <- asks insert_
      liftIO $ mapM_ ($ insertRRSet) rrss

-- | The `cacheEmptySection srcDom dom typ getRanked msg` caches two pieces of information from `msg`.
--   One is that the data for `dom` and `typ` are empty, and the other is the SOA record for the zone of
--   the sub-domains under `srcDom`.
--   The `getRanked` function returns the section with the empty information.
cacheEmptySection :: Domain -> Domain -> TYPE
                  -> (DNSMessage -> ([ResourceRecord], Ranking))
                  -> DNSMessage -> ContextT IO ()
cacheEmptySection srcDom dom typ getRanked msg =
  either ncWarn doCache takePair
  where
    doCache (soaDom, ncttl) = do
      cacheSOA
      cacheEmpty soaDom dom typ ncttl rank
    (_section, rank) = getRanked msg
    (takePair, cacheSOA) = getSection rankedAuthority refinesSOA msg
      where
        refinesSOA srrs = (single ps, take 1 rrs)  where (ps, rrs) = unzip $ foldr takeSOA [] srrs
        takeSOA rr@ResourceRecord { rrtype = SOA, rdata = rd } xs
          | rrname rr `DNS.isSubDomainOf` srcDom,
            Just soa <- DNS.fromRData rd   =  (fromSOA soa rr, rr) : xs
          | otherwise                      =  xs
        takeSOA _         xs     =  xs
        {- the minimum of the SOA.MINIMUM field and SOA's TTL
            https://datatracker.ietf.org/doc/html/rfc2308#section-3
            https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        fromSOA soa rr = (rrname rr, minimum [DNS.soa_minimum soa, rrttl rr, maxNCacheTTL])
        maxNCacheTTL = 21600
        single list = case list of
          []    ->  Left "no SOA records found"
          [x]   ->  Right x
          _:_:_ ->  Left "multiple SOA records found"
    ncWarn s
      | not $ null answer  =  logLines Log.DEBUG $
                              [ "cacheEmptySection: from-domain=" ++ show srcDom ++ ", domain=" ++ show dom ++ ": " ++ s
                              , "  because of non empty answers:"
                              ] ++
                              map (("  " ++) . show) answer
      | otherwise          =  logLines Log.NOTICE $
                              [ "cacheEmptySection: from-domain=" ++ show srcDom ++ ", domain=" ++ show dom ++ ": " ++ s
                              , "  authority section:"
                              ] ++
                              map (("  " ++) . show) (DNS.authority msg)

      where answer = DNS.answer msg

cacheEmpty :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ContextT IO ()
cacheEmpty srcDom dom typ ttl rank = do
  logLn Log.DEBUG $ "cacheEmpty: " ++ show (srcDom, dom, typ, ttl, rank)
  insertRRSet <- asks insert_
  liftIO $ insertSetEmpty srcDom dom typ ttl rank insertRRSet

---

logLines :: Log.Level -> [String] -> ContextT IO ()
logLines level xs = do
  putLines <- asks logLines_
  liftIO $ putLines level xs

logLn :: Log.Level -> String -> ContextT IO ()
logLn level = logLines level . (:[])

printResult :: Either QueryError DNSMessage -> IO ()
printResult = either print pmsg
  where
    pmsg msg =
      putStr $ unlines $
      ["answer:"] ++
      map show (DNS.answer msg) ++
      [""] ++
      ["authority:"] ++
      map show (DNS.authority msg) ++
      [""] ++
      ["additional:"] ++
      map show (DNS.additional msg) ++
      [""]

ppDelegation :: NE DEntry -> String
ppDelegation des = "\t" ++ (intercalate "\n\t" $ map (pp . bundle) $ groupBy ((==) `on` fst) $ map toT (fst des : snd des))
  where
    toT (DEwithAx d i) = (d, show i)
    toT (DEonlyNS d)   = (d, "")
    bundle xss@(x:_) = (fst x, filter (/= "") $ map snd xss)
    bundle []        = ("",[]) -- never reach
    pp (d,is) = show d ++ " " ++ show is
