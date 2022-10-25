module Output (pprResult) where

import Data.Monoid (Endo (..))
import Control.Monad.Trans.Writer (Writer, execWriter, tell)

import DNS.Types (DNSMessage, ResourceRecord (..), Question)
import qualified DNS.Types as DNS

----------------------------------------------------------------

type Print = Writer (Endo String)
type Printer a = a -> Print ()

----------------------------------------------------------------

pprResult :: DNSMessage -> String
pprResult = runPrinter result

runPrinter :: Printer a -> a -> String
runPrinter p = ($ "") . appEndo . execWriter . p

----------------------------------------------------------------

result :: Printer DNSMessage
result msg = do
  putQS $ DNS.question msg
  putRRS answers     $ DNS.answer     msg
  putRRS authoritys  $ DNS.authority  msg
  putRRS additionals $ DNS.additional msg

----------------------------------------------------------------

putQS :: [Question] -> Print ()
putQS [] = pure ()
putQS qs = do
  nl
  dsemi *> sp *> string "QUESTION SECTION:" *> nl
  mapM_ qq qs

qq :: Printer Question
qq q = do
  semi *> string (DNS.origName $ DNS.qname q)
  tab
  tab
  string $ cls $ DNS.qclass q
  tab
  string $ show $ DNS.qtype q
  nl

----------------------------------------------------------------

putRRS :: Printer [ResourceRecord] -> [ResourceRecord] -> Print ()
putRRS _   [] = pure ()
putRRS ppr rs = nl *> ppr rs

answers :: Printer DNS.Answers
answers = rrs "ANSWER SECTION:"

authoritys :: Printer DNS.AuthorityRecords
authoritys = rrs "AUTHORITY SECTION:"

additionals :: Printer DNS.AdditionalRecords
additionals = rrs "ADDITIONAL SECTION:"

rrs :: String -> Printer [DNS.ResourceRecord]
rrs name rs = do
  dsemi *> sp *> string name *> nl
  mapM_ rr rs

rr :: Printer ResourceRecord
rr r = do
  string $ DNS.origName $ rrname r
  tab
  string $ show $ rrttl r
  tab
  string $ cls $ rrclass r
  tab
  string $ show $ rrtype r
  tab
  string $ show $ rdata r
  nl

----------------------------------------------------------------

cls :: DNS.CLASS -> String
cls c | c == DNS.classIN = "IN"
      | otherwise        = "#<" ++ show c ++ ">"

----------------------------------------------------------------

char :: Printer Char
char = tell . Endo . (:)

string :: Printer String
string = mapM_ char

sepBy :: Printer a -> Print () -> Printer [a]
sepBy _ _ []     =  pure ()
sepBy p s (x:xs) =  p x *> mapM_ ((s *>) . p) xs

semi :: Print ()
semi = char ';'

dsemi :: Print ()
dsemi = semi *> semi

sp :: Print ()
sp = char ' '

tab :: Print ()
tab = char '\t'

nl :: Print ()
nl = char '\n'
