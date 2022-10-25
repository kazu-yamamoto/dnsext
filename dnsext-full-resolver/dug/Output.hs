{-# LANGUAGE RecordWildCards #-}

module Output (pprResult) where

import Control.Monad.Trans.Writer (Writer, execWriter, tell)
import Data.Maybe (catMaybes)
import Data.Monoid (Endo (..))

import DNS.Types

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
result DNSMessage{..} = do
  putHeader header
  nl
  dsemi *> sp *> string "OPTIONAL PSEUDO SECTION:" *> nl
  semi *> string (show ednsHeader) *> nl
  putQS question
  putRRS answers     answer
  putRRS authoritys  authority
  putRRS additionals additional

----------------------------------------------------------------

putHeader :: Printer DNSHeader
putHeader DNSHeader{..} = do
  dsemi *> sp *> string "HEADER SECTION:"
  nl
  semi *> string (opcd opcode)              *> char ',' *> sp
  string (show rcode)                       *> char ',' *> sp
  string "id: " *> string (show identifier)
  nl
  semi *> string "Flags:" *> sp *> putFlags flags
  nl
  where
    DNSFlags{..} = flags

putFlags :: Printer DNSFlags
putFlags DNSFlags{..} = sepBy string (string ", ") $ catMaybes xs
  where
    jst x str = if x then Just str else Nothing
    xs :: [Maybe String]
    xs = [ jst authAnswer   "Authoritative Answer"
         , jst trunCation   "Truncated Caution"
         , jst recDesired   "Recursion Desired"
         , jst recAvailable "Recursion Available"
         , jst authenData   "Authenticated Data"
         , jst chkDisable   "Checking Disabled"
         ]

opcd :: OPCODE -> String
opcd OP_STD    = "Standard query"
opcd OP_INV    = "Inverse query"
opcd OP_SSR    = "Server status request"
opcd OP_NOTIFY = "Change notification"
opcd OP_UPDATE = "Update request"
opcd x         = show x

----------------------------------------------------------------

putQS :: [Question] -> Print ()
putQS qs = do
  nl
  dsemi *> sp *> string "QUESTION SECTION:" *> nl
  mapM_ qq qs

qq :: Printer Question
qq Question{..} = do
  semi *> string (origName qname)
  tab
  tab
  string $ cls qclass
  tab
  string $ show qtype
  nl

----------------------------------------------------------------

putRRS :: Printer [ResourceRecord] -> [ResourceRecord] -> Print ()
putRRS ppr rs = nl *> ppr rs

answers :: Printer Answers
answers = rrs "ANSWER SECTION:"

authoritys :: Printer AuthorityRecords
authoritys = rrs "AUTHORITY SECTION:"

additionals :: Printer AdditionalRecords
additionals = rrs "ADDITIONAL SECTION:"

rrs :: String -> Printer [ResourceRecord]
rrs name rs = do
  dsemi *> sp *> string name *> nl
  mapM_ rr rs

rr :: Printer ResourceRecord
rr ResourceRecord{..} = do
  string $ origName rrname
  tab
  string $ show rrttl
  tab
  string $ cls rrclass
  tab
  string $ show rrtype
  tab
  string $ show rdata
  nl

----------------------------------------------------------------

cls :: CLASS -> String
cls c | c == classIN = "IN"
      | otherwise    = "#<" ++ show c ++ ">"

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
