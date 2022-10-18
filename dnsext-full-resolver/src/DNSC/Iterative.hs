{-# LANGUAGE OverloadedStrings #-}

module DNSC.Iterative (
  -- * resolve interfaces
  getReplyMessage,
  getReplyCached,
  runResolve,
  runResolveJust,
  newContext,
  runIterative,
  rootNS, Delegation,
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
  Context (..),
  normalizeName,
  ) where

-- GHC packages
import Control.Arrow ((&&&), first)
import Control.Applicative ((<|>))
import Control.Monad (when, unless, join, guard)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import qualified Data.ByteString.Char8 as B8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.Function (on)
import Data.Int (Int64)
import Data.Maybe (listToMaybe, isJust)
import Data.List (unfoldr, uncons, groupBy, sortOn, sort, intercalate)
import Data.Word8
import Data.Map (Map)
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Bits ((.|.), shiftL)
import Numeric (readDec, readHex, showHex)

-- other packages
import System.Random (randomR, getStdRandom)

-- dns packages
import Data.IP (IP (IPv4, IPv6), IPv4, IPv6, toIPv4 , toIPv6b)
import qualified Data.IP as IP
import DNS.Types
  (Domain, DNSError, TTL,
   TYPE(A, NS, AAAA, CNAME, SOA), ResourceRecord (ResourceRecord, rrname, rrtype, rdata),
   RCODE, DNSHeader, DNSMessage)
import DNS.IO (ResolvConf (..), FlagOp (FlagClear))
import qualified DNS.Types as DNS
import qualified DNS.IO as DNS

-- this package
import DNSC.RootServers (rootServers)
import DNSC.DNSUtil (lookupRaw)
import DNSC.Types (NE, Timestamp)
import qualified DNSC.Log as Log
import DNSC.Cache
  (Ranking (RankAdditional), rankedAnswer, rankedAuthority, rankedAdditional,
   insertSetFromSection, insertSetEmpty, Key, CRSet, Cache)
import qualified DNSC.Cache as Cache


validate :: Domain -> Bool
validate n = not (DNS.checkDomain Short.null n)
          && DNS.checkDomain (Short.all isAscii) n

normalizeName :: Domain -> Maybe Domain
normalizeName = normalize

-- nomalize (domain) name to absolute name
normalize :: Domain -> Maybe Domain
normalize s
  | DNS.checkDomain (== ".") s = Just "."
  -- empty part is not valid, empty name is not valid
  | validate rn   = Just nn
  | otherwise     = Nothing  -- not valid
  where
    (rn, nn) | DNS.checkDomain ("." `Short.isSuffixOf`) s =
               (DNS.modifyDomain Short.init s, s)
             | otherwise                                  = (s, s <> ".")

-- get parent name for valid name
parent :: Domain -> Domain
parent n
  | DNS.checkDomain Short.null dp = error "parent: empty name is not valid."
  | DNS.checkDomain (== ".") dp   = "."  -- parent of "." is "."
  | otherwise                     = DNS.modifyDomain (Short.drop 1) dp
  where
    dp = DNS.modifyDomain (Short.dropWhile (/= _period)) n

-- get domain list for normalized name
domains :: Domain -> [Domain]
domains name
  | DNS.checkDomain (== dot) name =  []
  | DNS.checkDomain (dot `Short.isSuffixOf`) name  =  name : unfoldr parent_ name
  | otherwise                 =  error "domains: normalized name is required."
 where
    dot = "." :: ShortByteString
    parent_ n
      | DNS.checkDomain (== dot) p = Nothing
      | otherwise                  = Just (p, p)
      where
        p = parent n

isSubDomainOf :: Domain -> Domain -> Bool
x `isSubDomainOf` y =  y `elem` (domains x ++ ["."])

-----

data Context =
  Context
  { logLines_ :: Log.Level -> [String] -> IO ()
  , disableV6NS_ :: !Bool
  , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
  , getCache_ :: IO Cache
  , currentSeconds_ :: IO Timestamp
  , timeString_ :: IO ShowS
  }

data QueryError
  = DnsError DNSError
  | NotResponse DNS.QorR DNSMessage
  | InvalidEDNS DNS.EDNSheader DNSMessage
  | HasError DNS.RCODE DNSMessage
  deriving Show

type DNSQuery = ExceptT QueryError (ReaderT Context IO)

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
type TimeCache = (IO Int64, IO ShowS)

newContext :: (Log.Level -> [String] -> IO ()) -> Bool -> UpdateCache -> TimeCache
           -> IO Context
newContext putLines disableV6NS (ins, getCache) (curSec, timeStr) = do
  let cxt = Context
        { logLines_ = putLines, disableV6NS_ = disableV6NS
        , insert_ = ins, getCache_ = getCache
        , currentSeconds_ = curSec, timeString_ = timeStr }
  return cxt

dnsQueryT :: (Context -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT = ExceptT . ReaderT

runDNSQuery :: DNSQuery a -> Context -> IO (Either QueryError a)
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

withNormalized :: Domain -> (Domain -> DNSQuery a) -> Context -> IO (Either QueryError a)
withNormalized n action =
  runDNSQuery $
  action =<< maybe (throwDnsError DNS.IllegalDomain) return (normalize n)

-- 返答メッセージを作る
getReplyMessage :: Context -> DNSHeader -> NE DNS.Question -> IO (Either String DNSMessage)
getReplyMessage cxt reqH qs@(DNS.Question bn typ, _) =
  (\ers -> replyMessage ers (DNS.identifier reqH) $ uncurry (:) qs)
  <$> withNormalized bn getResult cxt
  where
    getResult n = do
      guardRequestHeader reqH
      replyResult n typ

-- キャッシュから返答メッセージを作る
-- Nothing のときキャッシュ無し
-- Just Left はエラー
getReplyCached :: Context -> DNSHeader -> (DNS.Question, [DNS.Question]) -> IO (Maybe (Either String DNSMessage))
getReplyCached cxt reqH qs@(DNS.Question bn typ, _) =
  fmap mkReply . either (Just . Left) (Right <$>)
  <$> withNormalized bn getResult cxt
  where
    getResult n = do
      guardRequestHeader reqH
      replyResultCached n typ
    mkReply ers = replyMessage ers (DNS.identifier reqH) (uncurry (:) qs)

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])

-- 最終的な解決結果を得る
runResolve :: Context -> Domain -> TYPE
           -> IO (Either QueryError (([ResourceRecord] -> [ResourceRecord], Domain), Either Result DNSMessage))
runResolve cxt n typ = withNormalized n (`resolve` typ) cxt

-- 権威サーバーからの解決結果を得る
runResolveJust :: Context -> Domain -> TYPE -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust cxt n typ = withNormalized n (`resolveJust` typ) cxt

-- 反復後の委任情報を得る
runIterative :: Context -> Delegation -> Domain -> IO (Either QueryError Delegation)
runIterative cxt sa n = withNormalized n (iterative sa) cxt

-----

-- parse IPv4 8bit-parts from reverse-lookup domain
parseV4RevDomain :: Domain -> Either String [Int]
parseV4RevDomain dom = do
  rstr <- maybe (throw "suffix does not match") Right $ DNS.checkDomain (Short.stripSuffix sufV4) dom
  let rparts = Short.split _period rstr
      plen = length rparts
  maybe (throw $ "invalid number of parts split by dot: " ++ show rstr) Right
    $ guard (1 <= plen && plen <= 4)
  mapM getByte $ reverse rparts
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
    sufV4 = ".in-addr.arpa."

-- parse IPv6 4bit-parts from reverse-lookup domain
parseV6RevDomain :: Domain -> Either String [Int]
parseV6RevDomain dom = do
  rstr <- maybe (throw "suffix does not match") Right $ DNS.checkDomain (Short.stripSuffix sufV6) dom
  let rparts = Short.split _period rstr
      plen = length rparts
  maybe (throw $ "invalid number of parts split by dot: " ++ show rstr) Right
    $ guard (1 <= plen && plen <= 32)
  mapM getHexDigit $ reverse rparts
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
    sufV6 = ".ip6.arpa."

-- show IPv4 reverse-lookup domain from 8bit-parts
showV4RevDomain :: [Int] -> Domain
showV4RevDomain parts = DNS.ciName $ intercalate "." (map show $ reverse parts) ++ ".in-addr.arpa."

-- parse IPv6 reverse-lookup domain from 4bit-parts
showV6RevDomain :: [Int] -> Domain
showV6RevDomain parts = DNS.ciName $ intercalate "." (map (`showHex` "") $ reverse parts) ++ ".ip6.arpa."

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
      ResourceRecord { rrname = dom, rrtype = SOA, DNS.rrclass = DNS.classIN, DNS.rrttl = ncttl
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

    lookupNX :: Domain -> ReaderT Context IO (Maybe ([ResourceRecord], Ranking))
    lookupNX bn = maybe (return Nothing) (either (return . Just) inconsistent) =<< lookupType bn Cache.nxTYPE
      where inconsistent rrs = do
              logLn Log.NOTICE $ "resolve: inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
              return Nothing

    -- Nothing のときはキャッシュに無し
    -- Just Left のときはキャッシュに有るが CNAME レコード無し
    lookupCNAME :: Domain -> ReaderT Context IO (Maybe (Either [ResourceRecord] (Domain, ResourceRecord)))
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
  (msg, _nss@(srcDom, _)) <- resolveJust bn CNAME
  lift $ cacheAnswer srcDom bn CNAME msg
  return msg

{- 目的の TYPE のレコードの取得を試み、結果の DNSMessage を返す.
   結果が CNAME なら、その RR も返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
resolveTYPE :: Domain -> TYPE
            -> DNSQuery (DNSMessage, Maybe (Domain, ResourceRecord))  {- result msg and cname RR involved in -}
resolveTYPE bn typ = do
  (msg, _nss@(srcDom, _)) <- resolveJust bn typ
  cname <- lift $ getSectionWithCache rankedAnswer refinesCNAME msg
  let checkTypeRR =
        when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
          throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
  maybe (lift $ cacheAnswer srcDom bn typ msg) (const checkTypeRR) cname
  return (msg, cname)
    where
      refinesCNAME rrs = (fst <$> uncons ps, map snd ps)
        where ps = cnameList bn (,) rrs

cacheAnswer :: Domain -> Domain -> TYPE -> DNSMessage -> ReaderT Context IO ()
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
  nss <- iterative_ dc rootNS $ reverse $ domains n
  sa <- selectDelegation dc nss
  lift $ logLn Log.DEBUG $ "resolve-just: norec: " ++ show (sa, n, typ)
  (,) <$> norec sa n typ <*> pure nss
    where
      mdc = maxNotSublevelDelegation

-- ドメインに対する NS 委任情報
type Delegation = (Domain, NE DEntry)

data DEntry
  = DEwithAx !Domain !IP
  | DEonlyNS !Domain
  deriving Show

nsDomain :: DEntry -> Domain
nsDomain (DEwithAx dom _)  =  dom
nsDomain (DEonlyNS dom  )  =  dom

v4DEntryList :: Domain -> [DEntry] -> [DEntry]
v4DEntryList _      []          =  []
v4DEntryList _srcDom des@(de:_)  =  concat $ map skipAAAA $ byNS des
  where
    byNS = groupBy ((==) `on` nsDomain)
    skipAAAA = nullCase . filter (not . aaaaDE)
      where
        aaaaDE (DEwithAx _ (IPv6 {})) = True
        aaaaDE _                      = False
        nullCase     []    =  [DEonlyNS (nsDomain de)]
        nullCase es@(_:_)  =  es

-- {-# ANN rootNS ("HLint: ignore Use fromMaybe") #-}
-- {-# ANN rootNS ("HLint: ignore Use tuple-section") #-}
rootNS :: Delegation
rootNS =
  maybe
  (error "rootNS: bad configuration.")
  id
  $ takeDelegation (nsList "." (,) ns) as
  where
    (ns, as) = rootServers

-- 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
iterative :: Delegation -> Domain -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ reverse $ domains n

iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery Delegation
iterative_ _  nss []     = return nss
iterative_ dc nss (x:xs) =
  step nss >>=
  maybe
  (recurse nss xs)   -- NS が返らない場合は同じ NS の情報で子ドメインへ. 通常のホスト名もこのケース. ex. or.jp, ad.jp
  (`recurse` xs)
  where
    recurse = iterative_ dc  {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    lookupNX :: ReaderT Context IO Bool
    lookupNX = isJust <$> lookupCache name Cache.nxTYPE

    stepQuery :: Delegation -> DNSQuery (Maybe Delegation)  -- Nothing のときは委任情報無し
    stepQuery nss_@(srcDom, _) = do
      sa <- selectDelegation dc nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      lift $ logLn Log.INFO $ "iterative: norec: " ++ show (sa, name, A)
      msg <- norec sa name A
      lift $ delegationWithCache srcDom name msg

    step :: Delegation -> DNSQuery (Maybe Delegation)  -- Nothing のときは委任情報無し
    step nss_ = do
      let withNXC nxc
            | nxc        =  return Nothing
            | otherwise  =  stepQuery nss_
      maybe (withNXC =<< lift lookupNX) return =<< lift (lookupDelegation name)

-- If Nothing, it is a miss-hit against the cache.
-- If Just Nothing, cache hit but no delegation information.
lookupDelegation :: Domain -> ReaderT Context IO (Maybe (Maybe Delegation))
lookupDelegation dom = do
  disableV6NS <- asks disableV6NS_
  let lookupDEs ns = do
        let takeA    ResourceRecord { rrtype = A, rdata = rd }    xs
              | Just v4 <- DNS.rdataField rd DNS.a_ipv4    = DEwithAx ns (IPv4 v4) : xs
            takeA    _ xs = xs
            takeAAAA ResourceRecord { rrtype = AAAA, rdata = rd } xs
              | Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 = DEwithAx ns (IPv6 v6) : xs
            takeAAAA _ xs = xs
            lookupAxList typ takeAx = fmap (foldr takeAx [] . fst) <$> lookupCache ns typ

        lk4 <- lookupAxList A takeA
        lk6 <- lookupAxList AAAA takeAAAA
        return $ case lk4 <> lk6 of
          Nothing
            | ns `isSubDomainOf` dom  ->  []             {- miss-hit with sub-domain case cause iterative loop, so return null to skip this NS -}
            | otherwise               ->  [DEonlyNS ns]  {- the case both A and AAAA are miss-hit -}
          Just as                     ->  as             {- just return address records. null case is wrong cache, so return null to skip this NS -}
      noCachedV4NS es = disableV6NS && null (v4DEntryList dom es)
      fromDEs es
        | noCachedV4NS es  =  Nothing
        {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
        | otherwise        =  (Just . (,) dom) <$> uncons es
        {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
      getDelegation :: ([ResourceRecord], a) -> ReaderT Context IO (Maybe (Maybe Delegation))
      getDelegation (rrs, _) = do {- NS cache hit -}
        let nss = sort $ nsList dom const rrs
        case nss of
          []    ->  return $ Just Nothing  {- hit null NS list, so no delegation -}
          _:_   ->  fromDEs . concat <$> mapM lookupDEs nss

  maybe (return Nothing) getDelegation =<< lookupCache dom NS

-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache :: Domain -> Domain -> DNSMessage -> ReaderT Context IO (Maybe Delegation)
delegationWithCache srcDom dom msg =
  -- 選択可能な NS が有るときだけ Just
  maybe
  (ncache *> return Nothing)
  (fmap Just . withCache)
  $ takeDelegation nsps adds
  where
    withCache x = do
      cacheNS
      cacheAdds
      return x

    (nsps, cacheNS) = getSection rankedAuthority refinesNS msg
      where refinesNS = unzip . nsList dom (\ns rr -> ((ns, rr), rr))
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

takeDelegation :: [(Domain, ResourceRecord)] -> [ResourceRecord] -> Maybe Delegation
takeDelegation nsps adds = do
  (p@(_, rr), ps) <- uncons nsps
  let nss = map fst (p:ps)
  ents <- uncons $ concatMap (uncurry dentries) $ nsPairs (sort nss) addgroups
  return (rrname rr, ents)
  where
    addgroups = groupBy ((==) `on` rrname) $ sortOn ((,) <$> rrname <*> rrtype) adds
    nsPairs []     _gs            =  []
    nsPairs (d:ds)  []            =  (d, []) : nsPairs ds  []
    nsPairs (d:ds) (g:gs)
      | d <  an                   =  (d, []) : nsPairs ds (g:gs)
      | d == an                   =  (d, g)  : nsPairs ds  gs
      | otherwise {- d >  an  -}  =            nsPairs ds  gs  -- unknown additional RRs. just skip
      where
        an = rrname a
        (a:_) = g
    dentries d     []     =  [DEonlyNS d]
    dentries d as@(_:_)   =  foldr takeAxDE [] as
      where
        takeAxDE a xs = case a of
          ResourceRecord { rrtype = A   , rdata = rd }
            | Just v4 <- DNS.rdataField rd DNS.a_ipv4    ->  DEwithAx d (IPv4 v4) : xs
          ResourceRecord { rrtype = AAAA, rdata = rd }
            | Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 ->  DEwithAx d (IPv6 v6) : xs
          _                                                     ->  xs

nsList :: Domain -> (Domain ->  ResourceRecord -> a)
       -> [ResourceRecord] -> [a]
nsList dom h = foldr takeNS []
  where
    takeNS rr@ResourceRecord { rrtype = NS, rdata = rd } xs
      | rrname rr == dom, Just ns <- DNS.rdataField rd DNS.ns_domain  =  h ns rr : xs
    takeNS _         xs   =  xs

cnameList :: Domain -> (Domain -> ResourceRecord -> a)
          -> [ResourceRecord] -> [a]
cnameList dom h = foldr takeCNAME []
  where
    takeCNAME rr@ResourceRecord { rrtype = CNAME, rdata = rd } xs
      | rrname rr == dom, Just cn <- DNS.rdataField rd DNS.cname_domain  =  h cn rr : xs
    takeCNAME _      xs   =  xs

-- 権威サーバーから答えの DNSMessage を得る. 再起検索フラグを落として問い合わせる.
norec :: IP -> Domain -> TYPE -> DNSQuery DNSMessage
norec aserver name typ = dnsQueryT $ \cxt -> do
  now <- currentSeconds_ cxt
  rs <- DNS.makeResolvSeed conf
  either (Left . DnsError) (handleResponseError Left Right) <$>
    DNS.withResolver rs ( \resolver -> lookupRaw now resolver name typ )
  where
    conf = DNS.defaultResolvConf
           { resolvInfo = DNS.RCHostName $ show aserver
           , resolvTimeout = 5 * 1000 * 1000
           , resolvRetry = 1
           , resolvQueryControls = DNS.rdFlag FlagClear
           }

-- Select an authoritative server from the delegation information and resolve to an IP address.
-- If the resolution result is NODATA, IllegalDomain is returned.
selectDelegation :: Int -> Delegation -> DNSQuery IP
selectDelegation dc (srcDom, des) = do
  disableV6NS <- lift $ asks disableV6NS_
  let failEmptyDEs = do
        lift $ logLn Log.INFO $ "selectDelegation: server-fail: domain: " ++ show srcDom ++ ", delegation is empty."
        throwDnsError DNS.ServerFailure
      getDEs
        | disableV6NS  =  maybe failEmptyDEs pure $ uncons (v4DEntryList srcDom $ fst des : snd des)
        | otherwise    =  pure des
      selectDE = randomizedSelectN
  dentry <- liftIO . selectDE =<< getDEs

  let selectA = randomizedSelect
      ns = nsDomain dentry
      takeAx :: ResourceRecord -> [(IP, ResourceRecord)] -> [(IP, ResourceRecord)]
      takeAx rr@ResourceRecord { rrtype = A, rdata = rd } xs
        | rrname rr == ns, Just v4 <- DNS.rdataField rd DNS.a_ipv4  = (IPv4 v4, rr) : xs
      takeAx rr@ResourceRecord { rrtype = AAAA, rdata = rd } xs
        | not disableV6NS && rrname rr == ns,
          Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 = (IPv6 v6, rr) : xs
      takeAx _         xs  =  xs

      axList = foldr takeAx []

      refinesAx rrs = (ps, map snd ps)
        where ps = axList rrs

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
        let failEmptyAx = do
              lift $ logLn Log.NOTICE $ "selectDelegation: server-fail: NS: " ++ show ns ++ ", address is empty."
              throwDnsError DNS.ServerFailure
        maybe failEmptyAx pure =<< liftIO . selectA  {- 失敗時: NS に対応する A の返答が空 -}
          =<< maybe query1Ax (pure . axList . fst) =<< lift lookupAx

  a <- case dentry of
         DEwithAx   _ ip  ->  pure ip
         DEonlyNS   {}    ->  fst <$> resolveAXofNS
  lift $ logLn Log.DEBUG $ "selectDelegation: " ++ show (srcDom, (ns, a))

  return a

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

lookupCache :: Domain -> TYPE -> ReaderT Context IO (Maybe ([ResourceRecord], Ranking))
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
                  -> ReaderT Context IO (Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking))
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
           -> m -> (a, ReaderT Context IO ())
getSection getRanked refines msg =
  withSection $ getRanked msg
  where
    withSection (rrs0, rank) = (result, cacheSection srrs rank)
      where (result, srrs) = refines rrs0

getSectionWithCache :: (m -> ([ResourceRecord], Ranking))
                    -> ([ResourceRecord] -> (a, [ResourceRecord]))
                    -> m -> ReaderT Context IO a
getSectionWithCache get refines msg = do
  let (res, doCache) = getSection get refines msg
  doCache
  return res

cacheSection :: [ResourceRecord] -> Ranking -> ReaderT Context IO ()
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
                  -> DNSMessage -> ReaderT Context IO ()
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
          | rrname rr `isSubDomainOf` srcDom,
            Just soa <- DNS.fromRData rd   =  (fromSOA soa rr, rr) : xs
          | otherwise                      =  xs
        takeSOA _         xs     =  xs
        {- the minimum of the SOA.MINIMUM field and SOA's TTL
            https://datatracker.ietf.org/doc/html/rfc2308#section-3
            https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        fromSOA soa rr = (rrname rr, minimum [DNS.soa_minimum soa, DNS.rrttl rr, maxNCacheTTL])
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

cacheEmpty :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ReaderT Context IO ()
cacheEmpty srcDom dom typ ttl rank = do
  logLn Log.DEBUG $ "cacheEmpty: " ++ show (srcDom, dom, typ, ttl, rank)
  insertRRSet <- asks insert_
  liftIO $ insertSetEmpty srcDom dom typ ttl rank insertRRSet

---

logLines :: Log.Level -> [String] -> ReaderT Context IO ()
logLines level xs = do
  putLines <- asks logLines_
  liftIO $ putLines level xs

logLn :: Log.Level -> String -> ReaderT Context IO ()
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
