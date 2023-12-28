{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoStrict #-}

module DNS.ZoneFile.Parser where

import Control.Applicative
import Control.Monad
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State
import Data.Functor

-- dnsext-* packages
import Data.IP (IPv4, IPv6)
import qualified Data.Vector as V
import DNS.Types hiding (rrname, rrclass, rrttl, rrtype)
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.ZoneFile.Types hiding (Parser, runParser)
import qualified DNS.ZoneFile.Types as Poly

{- FOURMOLU_DISABLE -}
data Context =
    Context
    { cx_zone   :: Domain
    , cx_name   :: Domain
    , cx_ttl    :: TTL
    , cx_class  :: CLASS
    }

instance Show Context where
    show (Context z n t c) = unwords ["Context", show z, show n, show $ toInt t, show c]
      where toInt = fromIntegral :: TTL -> Int
{- FOURMOLU_ENABLE -}

defaultContext :: Context
defaultContext = Context "." "." 1800 IN

type Parser a = StateT Context (Poly.Parser Token [Token]) a

runParser :: Parser a -> Context -> [Token] -> Either String ((a, Context), [Token])
runParser p = Poly.runParser . runStateT p

setCx :: (a -> Context -> Context) -> a -> Parser a
setCx set_ x = modify (set_ x) $> x

setZone :: Domain -> Parser Domain
setZone = setCx (\x s -> s {cx_zone = x})

setName :: Domain -> Parser Domain
setName = setCx (\x s -> s {cx_name = x})

setTTL :: TTL -> Parser TTL
setTTL = setCx (\x s -> s {cx_ttl = x})

setClass :: CLASS -> Parser CLASS
setClass = setCx (\x s -> s {cx_class = x})

---

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> cx = Context "" "" 3600 IN

-- |
-- >>> runParser dot cx [Dot]
-- Right ((Dot,Context "." "." 3600 IN),[])
dot :: Parser Token
dot = lift $ this Dot

-- |
-- >>> runParser blank cx [Blank]
-- Right ((Blank,Context "." "." 3600 IN),[])
blank :: Parser Token
blank = lift $ this Blank

{- FOURMOLU_DISABLE -}
cstring :: Parser CString
cstring = lift $ do
    t <- poly_token
    case t of
        CS cs -> pure cs
        _     -> raise $ "Parser.cstring: not CString: " ++ show t

readable :: Read a => String -> Parser a
readable str =
    case [ x | (x, "") <- reads str ] of
        []   -> lift $  raise $ "Parser.readable: unable to read: " ++ str
        x:_  -> pure x
{- FOURMOLU_ENABLE -}

readCString :: Read a => Parser a
readCString = readable . fromCString =<< cstring

---

type Labels = [CString]

-- | not empty relative domain labels
rlabels' :: Parser (Labels -> Labels)
rlabels' = (++) <$> ( (:) <$> cstring <*> many (dot *> cstring) )

-- | absolute domain labels
alabels :: Parser Labels
alabels = (rlabels' <|> pure id {- root case -}) <*> (dot $> [])

rlabels :: Parser Labels
rlabels = rlabels' <*> ( toLabels <$> gets cx_zone )

toLabels :: IsRepresentation a CString => a -> Labels
toLabels = V.toList . toWireLabels

fromLabels :: IsRepresentation a CString => Labels -> a
fromLabels = fromWireLabels . V.fromList

-- | absolute domain name
-- >>> runParser adomain cx [CS "example",Dot,CS "net",Dot]
-- Right (("example.net.",Context "." "." 3600 IN),[])
adomain :: Parser Domain
adomain = fromLabels <$> alabels

-- | not empty relative domain name
-- >>> runParser rdomain cx{cx_zone = "net."} [CS "example"]
-- Right (("example.net.",Context "net." "." 3600 IN),[])
rdomain :: Parser Domain
rdomain = fromLabels <$> rlabels

{- FOURMOLU_DISABLE -}
-- |
-- >>> runParser domain cx [CS "b",Dot,CS "example",Dot,CS "net",Dot]
-- Right (("b.example.net.",Context "." "." 3600 IN),[])
-- >>> runParser domain cx{cx_zone = "example.net."} [CS "a"]
-- Right (("a.example.net.",Context "example.net." "." 3600 IN),[])
-- >>> runParser domain cx{cx_zone = "example.net."} [At]
-- Right (("example.net.",Context "example.net." "." 3600 IN),[])
domain :: Parser Domain
domain =
    adomain                         <|>
    rdomain                         <|>
    lift (this At) *> gets cx_zone

mailbox :: Parser Mailbox
mailbox = fromLabels <$> ( alabels  <|> rlabels )
{- FOURMOLU_ENABLE -}

-- |
-- >>> runParser seconds cx [CS "7200"]
-- Right ((7200(2 hours),Context "." "." 3600 IN),[])
seconds :: Parser Seconds
seconds = Seconds <$> readCString

ttl :: Parser TTL
ttl = seconds

-- |
-- >>> runParser class_ cx [CS "IN"]
-- Right ((IN,Context "." "." 3600 IN),[])
class_ :: Parser CLASS
class_ = lift (this $ CS "IN") $> IN

-- |
-- >>> runParser (type_ AAAA) cx [CS "AAAA"]
-- Right ((AAAA,Context "." "." 3600 IN),[])
type_ :: TYPE -> Parser TYPE
type_ ty = do
    t <- readCString
    guard (t == ty) <|> lift (raise $ "ztype: expected: " ++ show ty ++ ", actual: " ++ show t)
    pure t

---


-- |
-- >>> runParser ipv4 cx [CS "203",Dot,CS "0",Dot,CS "113",Dot,CS "3"]
-- Right ((203.0.113.3,Context "." "." 3600 IN),[])
ipv4 :: Parser IPv4
ipv4 = join $ readv4 <$> cstrstr <*> (dot *> cstrstr) <*> (dot *> cstrstr) <*> (dot *> cstrstr)
  where
    cstrstr = fromCString <$> cstring
    readv4 a b c d = readable $ a ++ "." ++ b ++ "." ++ c ++ "." ++ d

-- |
-- >>> runParser ipv6 cx [CS "2001:db8::3"]
-- Right ((2001:db8::3,Context "." "." 3600 IN),[])
ipv6 :: Parser IPv6
ipv6 = readCString

---

rdataA :: Parser RData
rdataA = rd_a <$> ipv4

rdataAAAA :: Parser RData
rdataAAAA = rd_aaaa <$> ipv6

rdataPTR :: Parser RData
rdataPTR = rd_ptr <$> domain

rdataTXT :: Parser RData
rdataTXT = rd_txt . txt <$> ( (:) <$> nbstring <*> many (blank *> nbstring) )
  where
    txt = Opaque.concat . map txtCString
    nbstring = mconcat <$> some (cstring <|> dot $> ".")

rdataMX :: Parser RData
rdataMX = rd_mx <$> readCString <*> (blank *> domain)

rdataNS :: Parser RData
rdataNS = rd_ns <$> domain

rdataCNAME :: Parser RData
rdataCNAME = rd_cname <$> domain

{- FOURMOLU_DISABLE -}
rdataSOA :: Parser RData
rdataSOA =
    rd_soa
    <$> domain <*> (blank *> mailbox) <*> (blank *> readCString)
    <*> (blank *> seconds) <*> (blank *> seconds) <*> (blank *> seconds) <*> (blank *> seconds)
{- FOURMOLU_ENABLE -}

---

{-- $ORIGIN <domain-name> [<comment>]
      --(normalized)-->
      $ORIGIN <blank> <domain-name>  -}
-- |
-- >>> runParser zoneOrigin cx [Directive D_Origin,Blank,CS "example",Dot,CS "net",Dot]
-- Right (("example.net.",Context "example.net." "." 3600 IN),[])
zoneOrigin :: Parser Domain
zoneOrigin = lift (this (Directive D_Origin) *> this Blank) *> adomain >>= setZone

{-- $TTL <ttl> [<comment>]
      --(normalized)-->
      $TTL <blank> <ttl>  -}
-- |
-- >>> runParser zoneTTL cx [Directive D_TTL,Blank,CS "7200"]
-- Right ((7200(2 hours),Context "." "." 7200 IN),[])
zoneTTL :: Parser TTL
zoneTTL = lift (this (Directive D_TTL) *> this Blank) *> ttl >>= setTTL

{- NOT SUPPORT --- $INCLUDE <file-name> [<domain-name>] [<comment>] -}

{-- <blank><rr> [<comment>]
    <domain-name><rr> [<comment>]
      --(normalized)-->
      (<domain-name>) <blank> <TTL> <blank> <class> <blank> <type> <blank> <RDATA>
      (<domain-name>) <blank> <class> <blank> <TTL> <blank> <type> <blank> <RDATA>
      (<domain-name>) <blank> <TTL> <blank> <type> <blank> <RDATA>
      (<domain-name>) <blank> <class> <blank> <type> <blank> <RDATA>               -}

rrname :: Parser Domain
rrname = optional domain >>= maybe (gets cx_name) setName

rrttl :: Parser TTL
rrttl = optional (blank *> ttl) >>= maybe (gets cx_ttl) setTTL

rrclass :: Parser CLASS
rrclass = optional (blank *> class_) >>= maybe (gets cx_class) setClass

{- FOURMOLU_DISABLE -}
rrTyRData :: (TYPE -> RData -> a) -> Parser a
rrTyRData mk =
    blank *>
    ( pair A      rdataA      <|>
      pair AAAA   rdataAAAA   <|>
      pair PTR    rdataPTR    <|>
      pair TXT    rdataTXT    <|>
      pair NS     rdataNS     <|>
      pair MX     rdataMX     <|>
      pair CNAME  rdataCNAME  <|>
      pair SOA    rdataSOA    )
  where
    pair ty rd = mk <$> type_ ty <*> (blank *> rd)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> runParser zoneRR cx [CS "example",Dot,CS "net",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "AAAA",Blank,CS "2001:db8::3"]
-- Right ((ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3},Context "." "example.net." 7200 IN),[])
-- >>> runParser zoneRR cx [CS "example",Dot,CS "net",Dot,Blank,CS "IN",Blank,CS "7200",Blank,CS "AAAA",Blank,CS "2001:db8::3"]
-- Right ((ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3},Context "." "example.net." 7200 IN),[])
-- >>> runParser zoneRR cx{cx_name = "example.net."} [Blank,CS "7200",Blank,CS "IN",Blank,CS "AAAA",Blank,CS "2001:db8::3"]
-- Right ((ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3},Context "." "example.net." 7200 IN),[])
-- >>> runParser zoneRR cx{cx_name = "example.net.", cx_ttl = 7200, cx_class = IN} [Blank,CS "AAAA",Blank,CS "2001:db8::3"]
-- Right ((ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3},Context "." "example.net." 7200 IN),[])
zoneRR :: Parser ResourceRecord
zoneRR =
    (pat1 <$> rrname <*> rrttl <*> rrclass >>= rrTyRData)  <|>
    (pat2 <$> rrname <*> rrclass <*> rrttl >>= rrTyRData)
 where
   pat1 = \name ttl_ cls typ rd -> ResourceRecord name typ cls ttl_ rd
   pat2 = \name cls ttl_ typ rd -> ResourceRecord name typ cls ttl_ rd
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
record :: Parser Record
record =
    R_RR      <$> zoneRR      <|>
    R_Origin  <$> zoneOrigin  <|>
    R_TTL     <$> zoneTTL
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
file :: Parser [Record]
file = many (record <* lift (this RSep))
{- FOURMOLU_ENABLE -}

-- |
-- >>> parseLineRR [CS "example",Dot,CS "net",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "AAAA",Blank,CS "2001:db8::3"] defaultContext
-- Right (ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3},Context "." "example.net." 7200 IN)
parseLineRR :: [Token] -> Context -> Either String (ResourceRecord, Context)
parseLineRR ts icontext = fst <$> runParser (zoneRR <* lift eof) icontext ts

-- |
-- >>> parseLineRecord [Directive D_Origin,Blank,CS "example",Dot,CS "net",Dot] defaultContext
-- Right (R_Origin "example.net.",Context "example.net." "." 1800 IN)
-- >>> parseLineRecord [CS "example",Dot,CS "net",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "AAAA",Blank,CS "2001:db8::3"] defaultContext
-- Right (R_RR (ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3}),Context "." "example.net." 7200 IN)
parseLineRecord :: [Token] -> Context -> Either String (Record, Context)
parseLineRecord ts icontext = fst <$> runParser (record <* lift eof) icontext ts

-- |
-- >>> parseFile [CS "example",Dot,CS "net",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "AAAA",Blank,CS "2001:db8::3",RSep]
-- Right ([R_RR (ResourceRecord {rrname = "example.net.", rrtype = AAAA, rrclass = IN, rrttl = 7200(2 hours), rdata = 2001:db8::3})],Context "." "example.net." 7200 IN)
parseFile :: [Token] -> Either String ([Record], Context)
parseFile = (fst <$>) . runParser (file <* lift eof) defaultContext
