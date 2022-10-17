module Output where

import Data.Monoid (Endo (..))
import Control.Monad.Trans.Writer (Writer, execWriter, tell)
import qualified Data.ByteString.Char8 as B8

import DNS.Types (DNSMessage, ResourceRecord (..))
import qualified DNS.Types as DNS


type Print = Writer (Endo String)
type Printer a = a -> Print ()

runPrinter :: Printer a -> a -> String
runPrinter p = ($ "") . appEndo . execWriter . p

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

banner :: Printer [String]
banner args = do
  semi
  sp *> string "<<>>" *> sp *> string "DiG-like" *> sp *> string "<<>>"
  sp *> (string `sepBy` sp) args
  nl

rr :: Printer ResourceRecord
rr r = do
  string $ DNS.origName $ rrname r
  tab
  string $ show $ rrttl r
  tab
  let cls
        | rrclass r == DNS.classIN = "IN"
        | otherwise                = "#<" ++ show (rrclass r) ++ ">"
  string cls
  tab
  string $ show $ rrtype r
  tab
  string $ show $ rdata r
  nl

rrs :: String -> Printer DNS.Answers
rrs name rs = do
  dsemi *> sp *> string name *> nl
  mapM_ rr rs

answers :: Printer DNS.Answers
answers = rrs "ANSWER SECTION:"

authoritys :: Printer DNS.AuthorityRecords
authoritys = rrs "AUTHORITY SECTION:"

additionals :: Printer DNS.AdditionalRecords
additionals = rrs "ADDITIONAL SECTION:"

result :: Printer ([String], DNSMessage)
result (args, msg) = do
  banner args
  let putRRS _   [] = pure ()
      putRRS ppr rs = nl *> ppr rs

  putRRS answers $ DNS.answer msg
  putRRS authoritys $ DNS.authority msg
  putRRS additionals $ DNS.additional msg

pprResult :: [String] -> DNSMessage -> String
pprResult = curry $ runPrinter result
