module DNSC.Iterative where

import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Maybe (MaybeT (..))
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
-- import Data.Monoid (Last (..))
import qualified Data.ByteString.Char8 as B8
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (isSuffixOf, unfoldr)

import Data.IP (IP (IPv4, IPv6))
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear), DNSError, RData (..),
   TYPE(A), ResourceRecord (ResourceRecord, rrname, rdata), DNSMessage)
import qualified Network.DNS as DNS


type Name = String

validate :: Name -> Bool
validate = not . null
-- validate = all (not . null) . splitOn "."

-- nomalize (domain) name to absolute name
normalize :: Name -> Maybe Name
normalize "." = Just "."
normalize s
  -- empty part is not valid, empty name is not valid
  | validate rn   = Just nn
  | otherwise     = Nothing  -- not valid
  where
    (rn, nn) | "." `isSuffixOf` s = (init s, s)
             | otherwise          = (s, s ++ ".")

-- get parent name for valid name
parent :: String -> String
parent n
  | null dotp    =  error "parent: empty name is not valid."
  | dotp == "."  =  "."  -- parent of "." is "."
  | otherwise    =  tail dotp
  where
    dotp = dropWhile (/= '.') n

-- get domain list for normalized name
domains :: Name -> [Name]
domains "."  = []
domains name
  | "." `isSuffixOf` name = name : unfoldr parent_ name
  | otherwise             = error "domains: normalized name is required."
  where
    parent_ n
      | p == "."   =  Nothing
      | otherwise  =  Just (p, p)
      where
        p = parent n

-----

rootServers :: [IP]
rootServers =
  [ read "198.41.0.4"     -- a
  , read "192.58.128.30"  -- j
  , read "2001:503:ba3e::2:30"
  ]

-----

{-
type Error = Last DNSError

dnsError :: DNSError -> Error
dnsError = Last . Just

mapDnsError :: Either DNSError a -> Either Error a
mapDnsError = either (Left . dnsError) Right
 -}

type DNSQuery = ExceptT DNSError IO

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバの名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバの初期値はルートサーバとなる.
 -}

withNormalized :: Name -> (Name -> DNSQuery a) -> IO (Either DNSError a)
withNormalized n action = runExceptT $ do
  action =<< maybe (throwE DNS.IllegalDomain) return (normalize n)

runQuery :: Name -> TYPE -> IO (Either DNSError DNSMessage)
runQuery n typ = withNormalized n (`query` typ)

-- 反復検索を使ったクエリ. 結果が CNAME なら繰り返し解決する.
query :: Name -> TYPE -> DNSQuery DNSMessage
query n typ = do
  msg <- query1 n typ
  -- TODO: 目的の TYPE と CNAME が両方あったらエラーにする
  let cname = listToMaybe $ mapMaybe takeCNAME $ DNS.answer msg
  maybe (pure msg) (uncurry resolveCNAME) cname
  where

    takeCNAME (rr@ResourceRecord { rdata = RD_CNAME cn})
      | rrname rr == B8.pack n  =  Just (cn, rr)
    takeCNAME _                 =  Nothing

    -- TODO: CNAME 解決の回数制限
    resolveCNAME cn cnRR = do
      x <- query (B8.unpack cn) typ
      lift $ cacheRR cnRR
      return x

runQuery1 :: Name -> TYPE -> IO (Either DNSError DNSMessage)
runQuery1 n typ = withNormalized n (`query1` typ)

-- 反復検索を使ったクエリ. CNAME は解決しない.
query1 :: Name -> TYPE -> DNSQuery DNSMessage
query1 n typ = do
  when debug $ liftIO $ putStrLn $ "query1: " ++ show (n, typ)
  roota <- maybe (throwE DNS.BadConfiguration) pure =<< liftIO selectRoot
  sa <- iterative roota n
  ExceptT $ qNorec1 sa (B8.pack n) typ

selectRoot :: IO (Maybe IP)
selectRoot =
  -- TODO: customize selection
  -- naive implementation
  return $ listToMaybe as
  where
    as = rootServers

runIterative :: IP -> Name -> IO (Either DNSError IP)
runIterative sa n = withNormalized n $ iterative sa

-- 反復検索でドメインの NS のアドレスを得る
iterative :: IP -> Name -> DNSQuery IP
iterative sa n = iterative_ sa $ reverse $ domains n

-- 反復検索の本体
iterative_ :: IP -> [Name] -> DNSQuery IP
iterative_ sa []     = return sa  -- 最後に返った NS
iterative_ sa (x:xs) = do
  when debug $ liftIO $ putStrLn $ "iterative: " ++ show (sa, name)
  msg <- ExceptT $ qstep sa name
  selectAuthNS name msg >>=
    maybe
    (iterative_ sa xs)    -- ex. or.jp, ad.jp, NS が返らない場合は同じ server address で子ドメインへ. 通常のホスト名もこのケース
    (\nsa -> iterative_ nsa xs)
  where
    name = B8.pack x

qstep :: IP -> Domain -> IO (Either DNSError DNSMessage)
qstep aserver name = qNorec1 aserver name A

qNorec1 :: IP -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
qNorec1 aserver name typ = do
  rs <- DNS.makeResolvSeed conf
  DNS.withResolver rs $ \resolver -> DNS.lookupRaw resolver name typ
  where
    conf = DNS.defaultResolvConf
           { resolvInfo = DNS.RCHostName $ show aserver
           , resolvTimeout = 5 * 1000 * 1000
           , resolvRetry = 2
           , resolvQueryControls = DNS.rdFlag FlagClear
           }

-- authority section 内の、Domain に対応する NS レコードが一つも無いときに Nothing
-- そうでなければ、additional section 内の NS の名前に対応する A を利用してアドレスを得る
-- NS の名前に対応する A が無いときには反復検索で解決しに行く (PTR 解決のときには glue レコードが無い)
selectAuthNS :: Domain -> DNSMessage -> DNSQuery (Maybe IP)
selectAuthNS dom msg = runMaybeT $ do
  (ns, nsRR) <- MaybeT $ liftIO $ selectNS $ mapMaybe takeNS $ DNS.authority msg

  let resolveNS :: DNSQuery IP
      resolveNS =
        (maybe (query1AofNS ns) pure =<<) . runMaybeT $ do
          (a, aRR) <- MaybeT $ liftIO $ selectA $ mapMaybe (takeAx ns) $ DNS.additional msg
          when debug $ liftIO $ putStrLn $ "selectAuthNS: " ++ show (dom, (ns, a))
          lift $ cacheVerifiedNS a aRR
          return a

      cacheVerifiedNS :: IP -> ResourceRecord -> ExceptT DNSError IO ()
      cacheVerifiedNS a aRR  = do
        good <- verifyA aRR
        if good
          then liftIO $ do cacheRR nsRR
                           cacheRR aRR
          else do liftIO $ putStrLn $ "selectAuthNS: verification failed: " ++ show (ns, a)
                  throwE DNS.IllegalDomain  -- 失敗時: NS に対応する A の verify 失敗

  lift resolveNS

  where
    query1AofNS :: Domain -> DNSQuery IP
    query1AofNS ns =
      maybe (throwE DNS.IllegalDomain) (pure . fst)  -- 失敗時: NS に対応する A の返答が空
      . listToMaybe . mapMaybe (takeAx ns) . DNS.answer
      =<< query1 (B8.unpack ns) A

    takeNS (rr@ResourceRecord { rdata = RD_NS ns})
      | rrname rr == dom  =  Just (ns, rr)
    takeNS _              =  Nothing

    takeAx ns (rr@ResourceRecord { rdata = RD_A ipv4 })
      | rrname rr == ns  =  Just (IPv4 ipv4, rr)
    takeAx ns (rr@ResourceRecord { rdata = RD_AAAA ipv6 })
      | rrname rr == ns  =  Just (IPv6 ipv6, rr)
    takeAx _  _          =  Nothing

selectNS :: [a] -> IO (Maybe a)
selectNS rs =
  -- TODO: customize selection
  -- naive implementation
  return $ listToMaybe rs

selectA :: [a] -> IO (Maybe a)
selectA as = do
  -- when (null as) $ putStrLn $ "selectA: warning: zero address list is passed." -- no glue record?
  -- TODO: customize selection
  -- naive implementation
  return $ listToMaybe as

verifyA :: ResourceRecord -> DNSQuery Bool
verifyA _ = return True
-- TODO: reverse lookup to verify

cacheRR :: ResourceRecord -> IO ()
cacheRR rr = do
  when debug $ putStrLn $ "cacheRR: " ++ show rr

debug :: Bool
debug = True

printResult :: Either DNSError DNSMessage -> IO ()
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

-----

_examples :: IO ()
_examples =
  mapM_ ((printResult =<<) . uncurry runQuery)
  [ ("google.com", DNS.NS)
  , ("iij.ad.jp", DNS.NS)
  , ("google.com", DNS.MX)
  , ("iij.ad.jp", DNS.MX)
  , ("www.google.com", DNS.A)
  , ("www.iij.ad.jp", DNS.A)
  , ("5.0.130.210.in-addr.arpa.", DNS.PTR) -- 210.130.0.5
  , ("porttest.dns-oarc.net", DNS.TXT)
  ]
