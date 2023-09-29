-- GHC packages
import Control.Concurrent (threadDelay)
import qualified Control.Exception as E
import Control.Monad ((<=<))
import Data.Char (toUpper)
import Data.Function (on)
import Data.List (intercalate, sort, sortOn)
import Data.String (fromString)
import Data.UnixTime (UnixTime (..), getUnixTime)
import Data.Word (Word16)
import Foreign.C.Types (CTime (..))
import System.Environment (getArgs)
import Text.Read (readEither)

-- dnsext-* package

import DNS.Do53.Client (
    FlagOp (..),
    defaultResolvActions,
    ractionGenId,
    ractionGetTime,
    ractionLog,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolvEnv (..),
    ResolvInfo (..),
    defaultResolvInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.Types (
    CLASS (IN),
    DNSError,
    DNSMessage,
    Domain,
    ResourceRecord,
    TYPE (..),
 )
import qualified DNS.Types as DNS

run
    :: (String, Word16)
    -> (String, Word16)
    -> [String]
    -> IO ()
run (h1, p1) (h2, p2) inputs = do
    re1 <- mkRE h1 p1
    re2 <- mkRE h2 p2
    let step = putStrLn <=< either (return . skip) (uncurry $ doCompare re1 re2) . getParam
    mapM_ step inputs
  where
    skip xs = intercalate "\t" $ "3" : xs
    getParam s = case words s of
        (h : tn : _) -> do
            typ <- readTYPE s tn
            Right (fromString h, typ)
        _ -> Left [s, "run: unknown input form"]
    readTYPE s tn = case map toUpper tn of
        "A" -> Right A
        "AAAA" -> Right AAAA
        "MX" -> Right MX
        "PTR" -> Right PTR
        "SRV" -> Right SRV
        "NS" -> Right NS
        "TXT" -> Right TXT
        _ -> Left [s, "run: unsupported type: " ++ tn]

mkRE :: String -> Word16 -> IO ResolvEnv
mkRE host port = renv <$> DNS.newConcurrentGenId
  where
    ris genId =
        [ defaultResolvInfo
            { rinfoHostName = host
            , rinfoPortNumber = fromIntegral port
            , rinfoActions =
                defaultResolvActions
                    { ractionGenId = genId
                    , ractionGetTime = getUnixTime >>= \(UnixTime (CTime now) _) -> pure now
                    , ractionLog = \_ _ _ -> pure ()
                    }
            }
        ]
    renv genId =
        ResolvEnv
            { renvResolver = udpTcpResolver 3 (32 * 1024) -- 3 is retry
            , renvConcurrent = False
            , renvResolvInfos = ris genId
            }

doCompare :: ResolvEnv -> ResolvEnv -> Domain -> TYPE -> IO String
doCompare re1 re2 name typ = do
    e1 <- queries re1 name typ
    e2 <- queries re2 name typ
    let (code, note) = compareResult e1 e2
    return $ intercalate "\t" [show code, DNS.toRepresentation name, show typ, note]

queries
    :: ResolvEnv
    -> Domain
    -> TYPE
    -> IO (Either DNSError DNSMessage)
queries re name typ = recurse (1 :: Int)
  where
    recurse n
        | n <= 0 = fail "queries.recurse: positive integer required."
        | n == 1 = query1
        | otherwise = do
            let retry = recurse $ pred n
                dnsError _ = threadDelay (1000 * 1000) *> retry
                dnsMessage msg
                    | rcode msg == DNS.ServFail = retry
                    | otherwise = pure $ Right msg
            either dnsError dnsMessage =<< query1

    query1 = query re name typ
    rcode = DNS.rcode . DNS.flags . DNS.header

query
    :: ResolvEnv
    -> Domain
    -> TYPE
    -> IO (Either DNSError DNSMessage)
query re name typ =
    E.try (getMsg <$> DNS.resolve re (DNS.Question name typ IN) (DNS.rdFlag FlagSet))
  where
    getMsg (DNS.Result{DNS.resultReply = DNS.Reply{DNS.replyDNSMessage = msg}}) = msg

type Result = Either DNSError DNSMessage

compareResult :: Result -> Result -> (Int, String)
compareResult x1 x2 = case (x1, x2) of
    (Left e1, Left e2) -> compareDnsError e1 e2
    (Right m1, Right m2) -> compareMessage m1 m2
    (Right m1, Left e2) -> (2, "reply and error does not match: " ++ show (rcode m1, e2))
    (Left e1, Right m2) -> (2, "error and reply does not match: " ++ show (e1, rcode m2))
  where
    compareDnsError e1 e2
        | e1 == e2 = (0, "OK, same dns-errors")
        | otherwise = (1, "dns-error not match: " ++ show (e1, e2))
    compareMessage m1 m2
        | not (isResp m1) || not (isResp m2) = (1, "isResponse not match: " ++ show (isResp m1, isResp m2))
        | rcode m1 /= rcode m2 = (1, "rcode not match: " ++ show (rcode m1, rcode m2))
        | ra m1 /= ra m2 =
            (1, "recAvailable not match: " ++ show (ra m1, ra m2))
        | rd m1 /= rd m2 = (1, "recDesired not match: " ++ show (rd m1, rd m2))
        | neqAnswer1 m1 m2 =
            ( 1
            , "answer types not match: "
                ++ show (DNS.answer m1)
                ++ ", "
                ++ show (DNS.answer m2)
            )
        | neqAnswer2 m1 m2 =
            ( 2
            , "answer data not match: "
                ++ show m1
                ++ ", "
                ++ show (DNS.answer m2)
            )
        | neqAuthority2 m1 m2 =
            ( 2
            , "authority data not match: "
                ++ show (DNS.authority m1)
                ++ ", "
                ++ show (DNS.authority m2)
            )
        | otherwise = (0, "OK, replies match")

    isResp = DNS.isResponse . flags
    rcode = DNS.rcode . flags
    ra = DNS.recAvailable . flags
    rd = DNS.recDesired . flags
    flags = DNS.flags . DNS.header
    neqAnswer1 m1 m2 = not $ (eqSection1 `on` DNS.answer) m1 m2
    neqAnswer2 m1 m2 = not $ (eqSection2 `on` DNS.answer) m1 m2
    neqAuthority2 m1 m2 = not $ (eqSection2 `on` DNS.authority) m1 m2

eqSection2 :: [ResourceRecord] -> [ResourceRecord] -> Bool
eqSection2 s1 s2 =
    length s1 == length s2
        && all (uncurry (==)) (zip (reg s1) (reg s2))
  where
    fields = (,,,) <$> DNS.rrname <*> DNS.rrtype <*> DNS.rrclass <*> DNS.rdata
    reg = sortOn (\(n, t, c, _) -> (n, t, c)) . map fields

-- only check name, type, class
eqSection1 :: [ResourceRecord] -> [ResourceRecord] -> Bool
eqSection1 s1 s2 =
    length s1 == length s2
        && all (uncurry (==)) (zip (reg s1) (reg s2))
  where
    fields = (,,) <$> DNS.rrname <*> DNS.rrtype <*> DNS.rrclass
    reg = sort . map fields

---

main :: IO ()
main = do
    args <- getArgs
    let parseAddr s = case break (== ':') s of
            (_, []) -> return (s, 53) :: IO (String, Word16)
            (h, _ : p) -> (,) h <$> either parseError return (readEither p)
              where
                parseError e = fail $ "failed to parse port number: " ++ p ++ ": " ++ e
    (a1, a2, getInputs) <- case args of
        s1 : s2 : xs -> (,,) <$> parseAddr s1 <*> parseAddr s2 <*> pure inputs
          where
            inputs = case xs of
                [] -> getContents
                fn : _ -> readFile fn
        _ -> fail "two server addresses required."
    run a1 a2 . lines =<< getInputs
