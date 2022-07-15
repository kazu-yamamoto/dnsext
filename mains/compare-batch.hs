
-- ghc packages
import Control.Concurrent (threadDelay)
import Control.Monad ((<=<))
import Data.Char (toUpper)
import Data.Function (on)
import Data.List (sort, intercalate)
import Data.Int (Int64)
import Data.Word (Word16)
import qualified Data.ByteString.Char8 as B8
import Data.Time.Clock.System (getSystemTime, systemSeconds)
import System.Environment (getArgs)
import Text.Read (readEither)

-- dns packages
import Network.DNS
  (ResolvConf (..), ResolvSeed, Domain, TYPE (..),
   DNSError, DNSMessage, ResourceRecord)
import qualified Network.DNS as DNS

-- thi package
import DNSC.DNSUtil (lookupRaw)
import DNSC.Cache (lowerAnswer, lowerAuthority)


run :: (String, Word16)
    -> (String, Word16)
    -> [String]
    -> IO ()
run (h1, p1) (h2, p2) inputs = do
  rs1 <- mkRS h1 p1
  rs2 <- mkRS h2 p2
  let step = putStrLn <=< either (return . skip) (uncurry $ doCompare rs1 rs2) . getParam
  mapM_ step inputs
  where
    skip xs = intercalate "\t" $ "3" : xs
    getParam s = case words s of
      (h:tn:_)  ->  do
        typ <- readTYPE s tn
        Right (B8.pack h, typ)
      _         ->  Left [s, "run: unknown input form"]
    readTYPE s tn = case map toUpper tn of
      "A"     ->  Right A
      "AAAA"  ->  Right AAAA
      "MX"    ->  Right MX
      "PTR"   ->  Right PTR
      "SRV"   ->  Right SRV
      "NS"    ->  Right NS
      "TXT"   ->  Right TXT
      _       ->  Left [s, "run: unsupported type: " ++ tn]

mkRS :: String -> Word16 -> IO ResolvSeed
mkRS host port =
  DNS.makeResolvSeed
  DNS.defaultResolvConf
  { resolvInfo = DNS.RCHostPort host (fromIntegral port)
  , resolvTimeout = 6 * 1000 * 1000
  , resolvRetry = 1
  }

doCompare :: ResolvSeed -> ResolvSeed -> Domain -> TYPE -> IO String
doCompare rs1 rs2 name typ = do
  e1 <- queries rs1 name typ
  e2 <- queries rs2 name typ
  let (code, note) = compareResult e1 e2
  return $ intercalate "\t" [show code, B8.unpack name, show typ, note]

queries :: ResolvSeed
        -> Domain -> TYPE
        -> IO (Either DNSError DNSMessage)
queries rs name typ = recurse (3 :: Int)
  where
    recurse n
      | n <= 0    =  fail "queries.recurse: positive integer required."
      | n == 1    =  query1
      | otherwise =  do
          let retry = recurse $ pred n
              dnsError _ = threadDelay (1000 * 1000) *> retry
              dnsMessage msg
                | rcode msg == DNS.ServFail  =  retry
                | otherwise                  =  pure $ Right msg
          either dnsError dnsMessage =<< query1

    query1 = do
      now <- systemSeconds <$> getSystemTime
      query now rs name typ
    rcode = DNS.rcode . DNS.flags . DNS.header

query :: Int64
      -> ResolvSeed
      -> Domain -> TYPE
      -> IO (Either DNSError DNSMessage)
query now rs name typ = DNS.withResolver rs $ \resolver -> lookupRaw now resolver name typ

type Result = Either DNSError DNSMessage

compareResult :: Result -> Result -> (Int, String)
compareResult x1 x2 = case (x1, x2) of
  (Left e1, Left e2)    ->  compareDnsError e1 e2
  (Right m1, Right m2)  ->  compareMessage m1 m2
  (Right m1, Left e2)   ->  (2, "reply and error does not match: " ++ show (rcode m1, e2))
  (Left e1, Right m2)   ->  (2, "error and reply does not match: " ++ show (e1, rcode m2))
  where
    compareDnsError e1 e2
      | e1 == e2              =  (0, "OK, same dns-errors")
      | otherwise             =  (1, "dns-error not match: " ++ show (e1, e2))
    compareMessage m1 m2
      | qr m1 /= qr m2        =  (1, "qOrR not match: " ++ show (qr m1, qr m2))
      | rcode m1 /= rcode m2  =  (1, "rcode not match: " ++ show (rcode m1, rcode m2))
      | ra m1 /= ra m2        =  (1, "recAvailable not match: " ++ show (ra m1, ra m2))
      | rd m1 /= rd m2        =  (1, "recDesired not match: " ++ show (rd m1, rd m2))
      | neqAnswer1 m1 m2      =  (1, "answer types not match: " ++ show (lowerAnswer m1) ++ ", " ++ show (lowerAnswer m2))
      | neqAnswer2 m1 m2      =  (2, "answer data not match: " ++ show (lowerAnswer m1) ++ ", " ++ show (lowerAnswer m2))
      | neqAuthority2 m1 m2   =  (2, "authority data not match: " ++ show (lowerAuthority m1) ++ ", " ++ show (lowerAuthority m2))
      | otherwise             =  (0, "OK, replies match")

    qr = DNS.qOrR . flags
    rcode = DNS.rcode . flags
    ra = DNS.recAvailable . flags
    rd = DNS.recDesired . flags
    flags = DNS.flags . DNS.header
    neqAnswer1 m1 m2 = not $ (eqSection1 `on` lowerAnswer) m1 m2
    neqAnswer2 m1 m2 = not $ (eqSection2 `on` lowerAnswer) m1 m2
    neqAuthority2 m1 m2 = not $ (eqSection2 `on` lowerAuthority) m1 m2

eqSection2 :: [ResourceRecord] -> [ResourceRecord] -> Bool
eqSection2 s1 s2 =
  length s1 == length s2 &&
  all (uncurry (==)) (zip (reg s1) (reg s2))
  where
    fields = (,,,) <$> DNS.rrname <*> DNS.rrtype <*> DNS.rrclass <*> DNS.rdata
    reg = sort . map fields

-- only check name, type, class
eqSection1 :: [ResourceRecord] -> [ResourceRecord] -> Bool
eqSection1 s1 s2 =
  length s1 == length s2 &&
  all (uncurry (==)) (zip (reg s1) (reg s2))
  where
    fields = (,,) <$> DNS.rrname <*> DNS.rrtype <*> DNS.rrclass
    reg = sort . map fields

---

main :: IO ()
main = do
  args <- getArgs
  let parseAddr s = case break (== ':') s of
        (_, [])   ->  return (s, 53)  :: IO (String, Word16)
        (h, _:p)  ->  (,) h <$> either parseError return (readEither p)
          where parseError e = fail $ "failed to parse port number: " ++ p ++ ": " ++ e
  (a1, a2, getInputs) <- case args of
    s1 : s2 : xs  ->  (,,) <$> parseAddr s1 <*> parseAddr s2 <*> pure inputs
      where inputs = case xs of
              []      ->  getContents
              fn : _  ->  readFile fn
    _             ->  fail "two server addresses required."
  run a1 a2 . lines =<< getInputs
