{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeSynonymInstances #-}

module DNS.Types.Domain (
    IsRepresentation(..)
  , Domain
  , superDomains
  , isSubDomainOf
  , Mailbox
  , getDomain
  , getDomainRFC1035
  , putDomain
  , putDomainRFC1035
  , putMailbox
  , putMailboxRFC1035
  , getMailbox
  , getMailboxRFC1035
  , CanonicalFlag (..)
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.Functor (($>))
import Data.Word8

import DNS.StateBinary
import DNS.Types.Error
import DNS.Types.Imports
import DNS.Types.Parser (Parser, Builder)
import qualified DNS.Types.Parser as P

-- $setup
-- >>> :set -XOverloadedStrings

class IsRepresentation a b where
    fromRepresentation :: b -> a
    toRepresentation   :: a -> b
    fromWireLabels     :: [b] -> a
    toWireLabels       :: a -> [b]

-- | The type for domain names. This holds both the
-- /presentation format/ and the /wire format/ internally.
--
-- The representation format is fully-qualified DNS domain names encoded
-- as ASCII A-labels, with \'.\' separators between labels.
-- The trailing \'.\' is added if missing.
-- Non-printing characters are escaped as @\\DDD@ (a backslash,
-- followed by three decimal digits). The special characters: @ \",
-- \$, (, ), ;, \@,@ and @\\@ are escaped by prepending a backslash.
--
-- The representation format is ASCII-only. Any conversion between
-- A-label 'Text's, and U-label 'Text' happens at whatever layer maps
-- user input to DNS names, or presents /friendly/ DNS names to the
-- user.  Not all users can read all scripts, and applications that
-- default to U-label format should ideally give the user a choice to
-- see the A-label format.  Examples:
--
-- A 'IllegalDomain' may be thrown when creating from the representation
-- format or decoding the wire format.
--
-- @
-- www.example.org.            -- Ordinary DNS name.
-- \_25.\_tcp.mx1.example.net. -- TLSA RR initial labels have \_ prefixes.
-- \\001.exotic.example.       -- First label is Ctrl-A!
-- just\\.one\\.label.example. -- First label is \"just.one.label\"
-- @
--

data Domain = Domain {
    -- The representation format. Case-sensitive, escaped.
    representation  :: ShortByteString
    -- Labels in wire format. Case-sensitive, not escaped.
  , wireLabels      :: [ShortByteString]
  -- | Eq and Ord key for Canonical DNS Name Order.
  --   Lower cases, not escaped.
  --   https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
  , canonicalLabels :: ~[ShortByteString]
  }

domain :: ShortByteString -> Domain
domain o = validateDomain $ Domain {
    representation  = addRoot o
  , wireLabels      = ls
  , canonicalLabels = reverse ls
  }
  where
    ~l = Short.map toLower o
    ~ls = unfoldr step l
    step x = case parseLabel _period x of
      Nothing        -> Nothing
      just@(Just (p, _))
        | p == ""    -> Nothing
        | otherwise  -> just

domainFromWireLabels :: [ShortByteString] -> Domain
domainFromWireLabels [] = Domain {
    representation  = "."
  , wireLabels      = []
  , canonicalLabels = []
  }
domainFromWireLabels ls = validateDomain $ Domain {
    representation  = rep
  , wireLabels      = ls
  , canonicalLabels = map (Short.map toLower) $ reverse ls
  }
  where
    rep = foldr (\l r -> escapeLabel _period l <> "." <> r) "" ls

instance Eq Domain where
    d0 == d1 = canonicalLabels d0 == canonicalLabels d1

-- | Ordering according to the DNSSEC definition.
--
-- >>> ("www.example.jp" :: Domain) >= "example.jp"
-- True
-- >>> ("example8.jp" :: Domain) >= "example.jp"
-- True
-- >>> ("example.jp" :: Domain) >= "example.com"
-- True
instance Ord Domain where
    d0 <= d1 = canonicalLabels d0 <= canonicalLabels d1

instance Show Domain where
    show d = "\"" ++ toRepresentation d ++ "\""

instance IsString Domain where
    fromString = fromRepresentation

-- | Appending two domains.
--
-- >>> ("www" :: Domain) <> "example.com"
-- "www.example.com."
-- >>> ("www." :: Domain) <> "example.com."
-- "www.example.com."
instance Semigroup Domain where
    d0 <> d1 = domainFromWireLabels (wireLabels d0 <> wireLabels d1)

instance IsRepresentation Domain ShortByteString where
    fromRepresentation = domain
    toRepresentation   = representation
    fromWireLabels     = domainFromWireLabels
    toWireLabels       = wireLabels

instance IsRepresentation Domain ByteString where
    fromRepresentation = domain . Short.toShort
    toRepresentation   = Short.fromShort . representation
    fromWireLabels     = domainFromWireLabels . map Short.toShort
    toWireLabels       = map Short.fromShort . wireLabels

instance IsRepresentation Domain String where
    fromRepresentation = domain . fromString
    toRepresentation   = shortToString . representation
    fromWireLabels     = domainFromWireLabels . map fromString
    toWireLabels       = map shortToString . wireLabels

addRoot :: RawDomain -> RawDomain
addRoot o
  | Short.null o            = "."
  | Short.last o == _period = o
  | otherwise               = o <> "."

----------------------------------------------------------------

validateDomain :: Domain -> Domain
validateDomain d
  | isIllegal (wireLabels d) = E.throw IllegalDomain
  | otherwise                = d

validateMailbox :: Mailbox -> Mailbox
validateMailbox m@(Mailbox d)
  | isIllegal (wireLabels d) = E.throw IllegalDomain
  | otherwise                = m

isIllegal :: [ShortByteString] -> Bool
isIllegal ls = sum is > 255 || any (> 63) is
  where
    is = map Short.length ls

----------------------------------------------------------------

-- | The type for mailbox whose internal is just 'Domain'.
--   The representation format must include \'@\'.
-- Examples:
--
-- @
-- hostmaster\@example.org.  -- First label is simply @hostmaster@
-- john.smith\@examle.com.   -- First label is @john.smith@
-- @
--

newtype Mailbox = Mailbox { fromMailbox :: Domain }

toMailbox :: Domain -> Mailbox
toMailbox = Mailbox

instance Eq Mailbox where
    Mailbox d0 == Mailbox d1 = d0 == d1

instance Ord Mailbox where
    Mailbox d0 <= Mailbox d1 = d0 <= d1

instance Show Mailbox where
    show (Mailbox d) = show d

instance IsString Mailbox where
    fromString = fromRepresentation

instance Semigroup Mailbox where
   Mailbox d0 <> Mailbox d1 = Mailbox (d0 <> d1)

mailbox :: ShortByteString -> Mailbox
mailbox o
  | Short.length o > 255 = E.throw $ DecodeError "The mailbox length is over 255"
mailbox o = validateMailbox $ Mailbox $ Domain {
    representation  = addRoot o
  , wireLabels      = ls
  , canonicalLabels = reverse ls
  }
  where
    ~l = Short.map toLower o
    ~ls = unfoldr step (l,0::Int)
    step (x,n) = case parseLabel sep x of
      Nothing        -> Nothing
      Just (p', x')
        | p' == ""    -> Nothing
        | otherwise   -> Just (p', (x', n+1))
      where
        sep | n == 0    = _at
            | otherwise = _period

mailboxFromWireLabels :: [ShortByteString] -> Mailbox
mailboxFromWireLabels [] = E.throw $ DecodeError "Broken mailbox"
mailboxFromWireLabels lls@(l:ls) = validateMailbox $ Mailbox $ Domain {
    representation  = rep
  , wireLabels      = lls
  , canonicalLabels = map (Short.map toLower) $ reverse lls
  }
  where
    rep = l <> "@" <> foldr (\x y -> escapeLabel _period x <> "." <> y) "" ls

instance IsRepresentation Mailbox ShortByteString where
    fromRepresentation = mailbox
    toRepresentation   = toRepresentation . fromMailbox
    fromWireLabels     = toMailbox . domainFromWireLabels
    toWireLabels       = wireLabels . fromMailbox

instance IsRepresentation Mailbox ByteString where
    fromRepresentation = mailbox . Short.toShort
    toRepresentation   = toRepresentation . fromMailbox
    fromWireLabels     = toMailbox . domainFromWireLabels . map Short.toShort
    toWireLabels       = map Short.fromShort . wireLabels . fromMailbox

instance IsRepresentation Mailbox String where
    fromRepresentation = mailbox . fromString
    toRepresentation   = toRepresentation . fromMailbox
    fromWireLabels     = toMailbox . domainFromWireLabels . map fromString
    toWireLabels       = map shortToString . wireLabels . fromMailbox

----------------------------------------------------------------

-- | Canonical-form flag.
-- For example, `Canonical` is used from DNSSEC extension.
--
-- ref. https://datatracker.ietf.org/doc/html/rfc4034#section-6.2 - Canonical RR Form
data CanonicalFlag
  = Original  -- ^ Original name
  | Canonical -- ^ Lower name without compressoin
  deriving (Eq, Show)

----------------------------------------------------------------

-- | Putting a domain name.
--   No name compression for new RRs.
putDomain :: CanonicalFlag -> Domain -> SPut ()
putDomain Original  Domain{..} = do
    mapM_ putPartialDomain wireLabels
    put8 0
putDomain Canonical Domain{..} = do
    mapM_ putPartialDomain $ reverse canonicalLabels
    put8 0

putPartialDomain :: RawDomain -> SPut ()
putPartialDomain = putLenShortByteString

----------------------------------------------------------------

putCompressedDomain :: Domain -> SPut ()
putCompressedDomain Domain{..} = putCompress wireLabels

putCompress :: [RawDomain] -> SPut ()
putCompress [] = put8 0
putCompress dom@(d:ds) = do
    mpos <- popPointer dom
    cur  <- builderPosition
    case mpos of
        Just pos -> putPointer pos
        _        -> do
            -- Pointers are limited to 14-bits!
            when (cur <= 0x3fff) $ pushPointer dom cur
            putPartialDomain d
            putCompress ds

putPointer :: Int -> SPut ()
putPointer pos = putInt16 (pos .|. 0xc000)

-- | Putting a domain name.
--   Names are compressed if possible.
--   This should be used only for CNAME, MX, NS, PTR and SOA.
putDomainRFC1035 :: CanonicalFlag -> Domain -> SPut ()
putDomainRFC1035 Original  dom = putCompressedDomain dom
putDomainRFC1035 Canonical dom = putDomain Canonical dom

----------------------------------------------------------------

-- | Putting a mailbox.
--   No name compression for new RRs.
putMailbox :: CanonicalFlag -> Mailbox -> SPut ()
putMailbox cf (Mailbox d) = putDomain cf d

-- | Putting a mailbox.
--   Names are compressed if possible.
--   This should be used only for SOA.
putMailboxRFC1035 :: CanonicalFlag -> Mailbox -> SPut ()
putMailboxRFC1035 cf (Mailbox d) = putDomainRFC1035 cf d

----------------------------------------------------------------

-- | Getting a domain name.
--   An error is thrown if name compression is used.
getDomain :: SGet Domain
getDomain = domainFromWireLabels <$> (parserPosition >>= getDomain' False)

-- | Getting a domain name.
-- Pointers MUST point back into the packet per RFC1035 Section 4.1.4.  This
-- is further interpreted by the DNS community (from a discussion on the IETF
-- DNSOP mailing list) to mean that they don't point back into the same domain.
-- Therefore, when starting to parse a domain, the current offset is also a
-- strict upper bound on the targets of any pointers that arise while processing
-- the domain.  When following a pointer, the target again becomes a stict upper
-- bound for any subsequent pointers.  This results in a simple loop-prevention
-- algorithm, each sequence of valid pointer values is necessarily strictly
-- decreasing!
getDomainRFC1035 :: SGet Domain
getDomainRFC1035 = domainFromWireLabels <$> (parserPosition >>= getDomain' True)

-- | Getting a mailbox.
--   An error is thrown if name compression is used.
getMailbox :: SGet Mailbox
getMailbox = mailboxFromWireLabels <$> (parserPosition >>= getDomain' False)

-- | Getting a mailbox.
getMailboxRFC1035 :: SGet Mailbox
getMailboxRFC1035 = mailboxFromWireLabels <$> (parserPosition >>= getDomain' True)

-- $
--
-- The case below fails to point far enough back, and triggers the loop
-- prevention code-path.
--
-- >>> let parser = getDomain' True 0
-- >>> let input = "\3foo\192\0\3bar\0"
-- >>> runSGet parser input
-- Left (DecodeError "invalid pointer: self pointing")
--

-- | Get a domain name.
--
-- Domain name compression pointers must always refer to a position
-- that precedes the start of the current domain name.  The starting
-- offsets form a strictly decreasing sequence, which prevents pointer
-- loops.
--
getDomain' :: Bool -> Int -> SGet [ShortByteString]
getDomain' allowCompression ptrLimit = do
    pos <- parserPosition
    c <- getInt8
    let n = getValue c
    getdomain pos c n
  where
    getdomain pos c n
      | c == 0 = return []
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return []
      | isPointer c && not allowCompression = failSGet "name compression is not allowed"
      | isPointer c = do
          d <- getInt8
          let offset = n * 256 + d
          when (offset == ptrLimit) $ failure "self pointing" pos offset
          when (offset > ptrLimit)  $ failure "forward pointing" pos offset
          mx <- popDomain offset
          case mx of
            Nothing -> failure "invalid area" pos offset
            Just lls -> do
                -- Supporting double pointers.
                pushDomain pos lls
                return lls
      | otherwise = do
          l <- getNShortByteString n
          -- Registering super domains
          ls <- getDomain' allowCompression ptrLimit
          let lls = l:ls
          pushDomain pos lls
          return lls
    -- The length label is limited to 63.
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6
    failure msg pos offset = failSGet $ "invalid pointer " ++ show offset ++ " at " ++ show pos ++ ": " ++ msg

----------------------------------------------------------------

-- | Decode a domain name in A-label form to a leading label and a tail with
-- the remaining labels, unescaping backlashed chars and decimal triples along
-- the way. Any U-label conversion belongs at the layer above this code.
-- 'Nothing' means that the input domain illegal.
--
-- >>> parseLabel _period "abc.def.xyz"
-- Just ("abc","def.xyz")
-- >>> parseLabel _period "abc.def.xyz."
-- Just ("abc","def.xyz.")
-- >>> parseLabel _period "xyz."
-- Just ("xyz","")
-- >>> parseLabel _period "abc\\.def.xyz"
-- Just ("abc.def","xyz")
-- >>> parseLabel _period "\\097.xyz"
-- Just ("a","xyz")
-- >>> parseLabel _period ".abc.def.xyz"
-- Nothing
-- >>> parseLabel _period "\\09.xyz"
-- Nothing
-- >>> parseLabel _period "\\513.xyz"
-- Nothing
parseLabel :: Word8 -> ShortByteString -> Maybe (ShortByteString, ShortByteString)
parseLabel sep dom
  | hasBackslash dom = case P.parse (labelParser sep mempty) dom of
      (Just hd, tl) -> check (hd, tl)
      _             -> Nothing
  | otherwise        = case Short.break (== sep) dom of
      r@(_,"")      -> Just r
      (hd,tl)       -> check (hd, Short.drop 1 tl)
  where
    hasBackslash = Short.any (== _backslash)
    check r@(hd, tl) | not (Short.null hd) || Short.null tl = Just r
                     | otherwise = Nothing

labelParser :: Word8 -> Builder -> Parser Builder
labelParser sep bld =
      (P.eof $> bld)
  <|> (P.satisfy (== sep) $> bld)
  <|> (simple  >>= \b -> labelParser sep (bld <> b))
  <|> (escaped >>= \b -> labelParser sep (bld <> b))
  where
    simple = P.toBuilder . fst <$> P.match skipUnescaped
      where
        skipUnescaped = P.skipSome $ P.satisfy notSepOrBslash
        notSepOrBslash w = w /= sep && w /= _backslash

    escaped = do
        P.skip (== _backslash)
        ddd <|> nonDDD
      where
        nonDDD = P.toBuilder <$> P.anyChar
        ddd = do
            x <- digit
            y <- digit <|> fail "an digit is expected (1)"
            z <- digit <|> fail "an digit is expected (2)"
            let d = 100 * x + 10 * y + z
            if d > 255 then fail "DDD should be less than 256" else pure (P.toBuilder (fromIntegral d :: Word8))
        digit :: Parser Int -- Word8 is not good enough for "d > 255"
        digit = fromIntegral . subtract _0 <$> P.satisfy isDigit

----------------------------------------------------------------

-- | Convert a wire-form label to presentation-form by escaping
-- the separator, special and non-printing characters.  For simple
-- labels with no bytes that require escaping we get back the input
-- Text asis with no copying or re-construction.
--
-- Note: the separator is required to be either \'.\' or \'\@\', but this
-- constraint is the caller's responsibility and is not checked here.
--
-- >>> escapeLabel _period "foo"
-- "foo"
-- >>> escapeLabel _period "foo.bar"
-- "foo\\.bar"
-- >>> escapeLabel _period "\x0aoo"
-- "\\010oo"
-- >>> escapeLabel _period "f\x7fo"
-- "f\\127o"
escapeLabel :: Word8 -> ShortByteString -> ShortByteString
escapeLabel sep label
  | isAllPlain label = label
  | otherwise        = toResult $ P.parse (labelEscaper sep mempty) label
  where
    isAllPlain = Short.all (isPlain sep)
    toResult (Just r, _) = r
    toResult _ = E.throw UnknownDNSError -- can't happen

labelEscaper :: Word8 -> Builder -> Parser Builder
labelEscaper sep bld0 = (P.eof $> bld0)
                     <|> (asis >>= \b -> labelEscaper sep (bld0 <> b))
                     <|> (esc  >>= \b -> labelEscaper sep (bld0 <> b))
  where
    -- Non-printables are escaped as decimal trigraphs, while printable
    -- specials just get a backslash prefix.
    esc = do
        w <- P.anyChar
        if w <= _space || w >= _del
        then let (q100, r100) = w `divMod` 100
                 (q10, r10)   = r100 `divMod` 10
              in pure (P.toBuilder _backslash  <>
                       P.toBuilder (_0 + q100) <>
                       P.toBuilder (_0 + q10)  <>
                       P.toBuilder (_0 + r10))
        else pure (P.toBuilder _backslash <> P.toBuilder w)

    -- Runs of plain bytes are recognized as a single chunk, which is then
    -- returned as-is.
    asis :: Parser Builder
    asis = do
       (r, _) <- P.match $ P.skipSome $ P.satisfy (isPlain sep)
       return $ P.toBuilder r

-- | In the presentation form of DNS labels, these characters are escaped by
-- prepending a backlash. (They have special meaning in zone files). Whitespace
-- and other non-printable or non-ascii characters are encoded via "\DDD"
-- decimal escapes. The separator character is also quoted in each label. Note
-- that '@' is quoted even when not the separator.
escSpecials :: [Word8]
escSpecials = [_quotedbl, _dollar, _parenleft, _parenright, _semicolon, _at, _backslash]

-- | Is the given byte the separator or one of the specials?
isSpecial :: Word8 -> Word8 -> Bool
isSpecial sep w = w == sep || elem w escSpecials

-- | Is the given byte a plain byte that reqires no escaping. The tests are
-- ordered to succeed or fail quickly in the most common cases. The test
-- ranges assume the expected numeric values of the named special characters.
-- Note: the separator is assumed to be either '.' or '@' and so not matched by
-- any of the first three fast-path 'True' cases.
isPlain :: Word8 -> Word8 -> Bool
isPlain sep w | w >= _del                    = False -- <DEL> + non-ASCII
              | w >= _bracketright           = True  -- ']'..'_'..'a'..'z'..'~'
              | w >= _A && w <= _bracketleft = True  -- 'A'..'Z'..'['
              | w >= _0 && w <= _colon       = True  -- '0'..'9'..':'
              | w <= _space                  = False -- non-printables
              | isSpecial sep w              = False -- one of the specials
              | otherwise                    = True  -- plain punctuation

----------------------------------------------------------------

shortToString :: ShortByteString -> String
shortToString = C8.unpack . Short.fromShort

----------------------------------------------------------------

-- | Creating super domains.
--
-- >>> superDomains "www.example.com"
-- ["www.example.com.","example.com.","com."]
-- >>> superDomains "www.example.com."
-- ["www.example.com.","example.com.","com."]
-- >>> superDomains "com."
-- ["com."]
-- >>> superDomains "."
-- []
superDomains :: Domain -> [Domain]
superDomains d = case wireLabels d of
  []   -> []
  [_]  -> [d]
  _:ls -> d : map domainFromWireLabels (init $ tails ls)

-- | Sub-domain or not.
--
-- >>> "www.example.com." `isSubDomainOf` "."
-- True
-- >>> "www.example.com." `isSubDomainOf` "com."
-- True
-- >>> "www.example.com." `isSubDomainOf` "example.com."
-- True
-- >>> "www.example.com." `isSubDomainOf` "www.example.com."
-- True
-- >>> "www.example.com." `isSubDomainOf` "foo-www.example.com."
-- False
isSubDomainOf :: Domain -> Domain -> Bool
_ `isSubDomainOf` "." = True
x `isSubDomainOf` y   = y `elem` superDomains x
