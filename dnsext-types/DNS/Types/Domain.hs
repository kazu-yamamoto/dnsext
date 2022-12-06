{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeSynonymInstances #-}

module DNS.Types.Domain (
    CaseInsensitiveName(..)
  , Domain
  , putDomain
  , getDomain
  , (<.>)
  , checkDomain
  , modifyDomain
  , addRoot
  , dropRoot
  , hasRoot
  , isIllegal
  , superDomains
  , isSubDomainOf
  , Mailbox
  , checkMailbox
  , modifyMailbox
  , putMailbox
  , getMailbox
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

class CaseInsensitiveName a b where
    ciName    :: b -> a
    origName  :: a -> b
    lowerName :: a -> b

-- $setup
-- >>> :set -XOverloadedStrings

-- | This type holds the /presentation form/ of fully-qualified DNS domain
-- names encoded as ASCII A-labels, with \'.\' separators between labels.
-- Non-printing characters are escaped as @\\DDD@ (a backslash, followed by
-- three decimal digits). The special characters: @ \", \$, (, ), ;, \@,@ and
-- @\\@ are escaped by prepending a backslash.  The trailing \'.\' is optional
-- on input, but is recommended, and is always added when decoding from
-- /wire form/.
--
-- The encoding of domain names to /wire form/, e.g. for transmission in a
-- query, requires the input encodings to be valid, otherwise a 'DecodeError'
-- may be thrown. Domain names received in wire form in DNS messages are
-- escaped to this presentation form as part of decoding the 'DNSMessage'.
--
-- This form is ASCII-only. Any conversion between A-label 'Text's,
-- and U-label 'Text' happens at whatever layer maps user input to DNS
-- names, or presents /friendly/ DNS names to the user.  Not all users
-- can read all scripts, and applications that default to U-label form
-- should ideally give the user a choice to see the A-label form.
-- Examples:
--
-- @
-- www.example.org.           -- Ordinary DNS name.
-- \_25.\_tcp.mx1.example.net.  -- TLSA RR initial labels have \_ prefixes.
-- \\001.exotic.example.       -- First label is Ctrl-A!
-- just\\.one\\.label.example.  -- First label is \"just.one.label\"
-- @
--

data Domain = Domain {
    origDomain      :: ShortByteString
  , lowerDomain     :: ShortByteString
  -- | Eq and Ord key for Canonical DNS Name Order
  --   https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
  , canonicalLabels :: ~[ShortByteString]
  }

domain :: ShortByteString -> Domain
domain o
  | Short.length o > 255 = E.throw $ DecodeError "The domain length is over 255"
domain o = Domain {
    origDomain = o
  , lowerDomain = n
  , canonicalLabels = reverse $ labels n
  }
  where
    n = Short.map toLower o
    labels = unfoldr step
    step x = case parseLabel _period x of
      Nothing        -> Nothing
      just@(Just (p, _))
        | p == ""    -> Nothing
        | otherwise  -> just

instance Eq Domain where
    d0 == d1 = canonicalLabels d0 == canonicalLabels d1

instance Ord Domain where
    d0 <= d1 = canonicalLabels d0 <= canonicalLabels d1

instance Show Domain where
    show d = "\"" ++ origName d ++ "\""

instance IsString Domain where
    fromString = ciName

instance Semigroup Domain where
    d0 <> d1 = domain (origDomain d0 <> origDomain d1)

instance CaseInsensitiveName Domain ShortByteString where
    ciName o = domain o
    origName  d = origDomain d
    lowerName d = lowerDomain d

instance CaseInsensitiveName Domain ByteString where
    ciName o = domain $ Short.toShort o
    origName  d = Short.fromShort $ origDomain d
    lowerName d = Short.fromShort $ lowerDomain d

instance CaseInsensitiveName Domain String where
    ciName o = domain $ fromString o
    origName  d = shortToString $ origDomain d
    lowerName d = shortToString $ lowerDomain d

-- | append operator using '.'
--
-- >>> "www" <.> "example.com"
-- "www.example.com"
-- >>> "com" <.> "."
-- "com."
(<.>) :: Domain -> Domain -> Domain
x <.> "." = x <> "."
x <.> y   = x <> "." <> y

infixr 6 <.>

checkDomain :: (ShortByteString -> a) -> Domain -> a
checkDomain f Domain{..} = f origDomain

modifyDomain :: (ShortByteString -> ShortByteString) -> Domain -> Domain
modifyDomain f Domain{..} = domain $ f origDomain

hasRoot :: Domain -> Bool
hasRoot d
  | Short.null o = False
  | otherwise    = Short.last o == _period
  where
    o = origDomain d

addRoot :: Domain -> Domain
addRoot d
  | Short.null o            = domain "."
  | Short.last o == _period = d
  | otherwise               = domain (o <> ".")
  where
   o = origDomain d

dropRoot :: Domain -> Domain
dropRoot d
  | Short.null o            = d
  | Short.last o == _period = domain $ Short.init o
  | otherwise               = d
  where
   o = origDomain d

----------------------------------------------------------------

badLength :: ShortByteString -> Bool
badLength o
    | Short.null o            = True
    | Short.last o == _period = Short.length o > 254
    | otherwise               = Short.length o > 253

isIllegal :: Domain -> Bool
isIllegal d
  | badLength o                  = True
  | not (_period `Short.elem` o) = True
  | _colon `Short.elem` o        = True
  | _slash `Short.elem` o        = True
  | any (\x -> Short.length x > 63)
        (Short.split _period o)  = True
  | otherwise                    = False
  where
    o = origDomain d

----------------------------------------------------------------

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the local part of an email address, and may contain internal
-- periods that are not label separators. Therefore, in mailboxes \@ is used as
-- the separator between the first and second labels, and any \'.\' characters
-- in the first label are not escaped.  The encoding is otherwise the same as
-- 'Domain' above. This is most commonly seen in the /rname/ of @SOA@ records,
-- and is also employed in the @mbox-dname@ field of @RP@ records.
-- On input, if there is no unescaped \@ character in the 'Mailbox', it is
-- reparsed with \'.\' as the first label separator. Thus the traditional
-- format with all labels separated by dots is also accepted, but decoding from
-- wire form always uses \@ between the first label and the domain-part of the
-- address.  Examples:
--
-- @
-- hostmaster\@example.org.  -- First label is simply @hostmaster@
-- john.smith\@examle.com.   -- First label is @john.smith@
-- @
--

data Mailbox = Mailbox {
    origMailbox  :: ShortByteString
  , lowerMailbox :: ShortByteString
  }

instance Eq Mailbox where
    Mailbox _ l0 == Mailbox _ l1 = l0 == l1

instance Ord Mailbox where
    Mailbox _ l0 <= Mailbox _ l1 = l0 <= l1

instance Show Mailbox where
    show d = "\"" ++ origName d ++ "\""

instance IsString Mailbox where
    fromString = ciName

instance Semigroup Mailbox where
   Mailbox o0 l0 <> Mailbox o1 l1 = Mailbox (o0 <> o1) (l0 <> l1)

mailbox :: ShortByteString -> Mailbox
mailbox o
  | Short.length o > 255 = E.throw $ DecodeError "The mailbox length is over 255"
mailbox o = Mailbox { origMailbox = o, lowerMailbox = n }
  where
    n = Short.map toLower o

instance CaseInsensitiveName Mailbox ShortByteString where
    ciName o = mailbox o
    origName  (Mailbox o _) = o
    lowerName (Mailbox _ n) = n

instance CaseInsensitiveName Mailbox ByteString where
    ciName o = mailbox $ Short.toShort o
    origName  (Mailbox o _) = Short.fromShort o
    lowerName (Mailbox _ n) = Short.fromShort n

instance CaseInsensitiveName Mailbox String where
    ciName o = mailbox $ fromString o
    origName  (Mailbox o _) = shortToString o
    lowerName (Mailbox _ n) = shortToString n

checkMailbox :: (ShortByteString -> a) -> Mailbox -> a
checkMailbox f (Mailbox o _) = f o

modifyMailbox :: (ShortByteString -> ShortByteString) -> Mailbox -> Mailbox
modifyMailbox f (Mailbox o l) = Mailbox (f o) (f l)

----------------------------------------------------------------

-- | Canonical-form flag.
-- For example, `Canonical` is used from DNSSEC extension.
--
-- ref. https://datatracker.ietf.org/doc/html/rfc4034#section-6.2 - Canonical RR Form
data CanonicalFlag
  = Compression
  | Canonical
  deriving (Eq, Show)

----------------------------------------------------------------

putDomain :: CanonicalFlag -> Domain -> SPut ()
putDomain cf@Compression Domain{..} = putDomain' _period cf origDomain
putDomain cf@Canonical   Domain{..} = putDomain' _period cf lowerDomain {- canonical form is lowercase and no name-compression. -}

putMailbox :: CanonicalFlag -> Mailbox -> SPut ()
putMailbox cf@Compression Mailbox{..} = putDomain' _at cf origMailbox
putMailbox cf@Canonical   Mailbox{..} = putDomain' _at cf lowerMailbox {- canonical form is lowercase and no name-compression. -}

putDomain' :: Word8 -> CanonicalFlag -> RawDomain -> SPut ()
putDomain' sep cf dom
    | Short.null dom || dom == "." = put8 0
    | otherwise = do
        mpos <- popPointer dom
        cur  <- builderPosition
        case mpos of
            Just pos | cf == Compression -> putPointer pos
            _                            -> do
                        -- Pointers are limited to 14-bits!
                        when (cur <= 0x3fff) $ pushPointer dom cur
                        putPartialDomain hd
                        putDomain' _period cf tl
  where
    (hd, tl) = go sep
      where
        go w = case parseLabel w dom of
            Just p
              -- Try with the preferred separator if present,
              -- else fall back to '.'.
              | w /= _period && Short.null (snd p) -> go _period
              | otherwise -> p
            Nothing -> E.throw $ DecodeError $ "invalid domain: " ++ shortToString dom

putPointer :: Int -> SPut ()
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: RawDomain -> SPut ()
putPartialDomain = putLenShortByteString

----------------------------------------------------------------

-- | Pointers MUST point back into the packet per RFC1035 Section 4.1.4.  This
-- is further interpreted by the DNS community (from a discussion on the IETF
-- DNSOP mailing list) to mean that they don't point back into the same domain.
-- Therefore, when starting to parse a domain, the current offset is also a
-- strict upper bound on the targets of any pointers that arise while processing
-- the domain.  When following a pointer, the target again becomes a stict upper
-- bound for any subsequent pointers.  This results in a simple loop-prevention
-- algorithm, each sequence of valid pointer values is necessarily strictly
-- decreasing!  The third argument to 'getDomain'' is a strict pointer upper
-- bound, and is set here to the position at the start of parsing the domain
-- or mailbox.
--
-- Note: the separator passed to 'getDomain'' is required to be either \'.\' or
-- \'\@\', or else 'unparseLabel' needs to be modified to handle the new value.
--

getDomain :: SGet Domain
getDomain = ciName <$> (parserPosition >>= getDomain' _period)

getMailbox :: SGet Mailbox
getMailbox = ciName <$> (parserPosition >>= getDomain' _at)

-- $
-- Pathological case: pointer embedded inside a label!  The pointer points
-- behind the start of the domain and is then absorbed into the initial label!
-- Though we don't IMHO have to support this, it is not manifestly illegal, and
-- does exercise the code in an interesting way.  Ugly as this is, it also
-- "works" the same in Perl's Net::DNS and reportedly in ISC's BIND.
--
-- >>> :{
-- let input = "\6\3foo\192\0\3bar\0"
--     parser = skipNBytes 1 >> getDomain' _period 1
--     Right (output, _) = runSGet parser input
--  in output == "foo.\\003foo\\192\\000.bar."
-- :}
-- True
--
-- The case below fails to point far enough back, and triggers the loop
-- prevention code-path.
--
-- >>> :{
-- let input = "\6\3foo\192\1\3bar\0"
--     parser = skipNBytes 1 >> getDomain' _period 1
--     Left (DecodeError err) = runSGet parser input
--  in err
-- :}
-- "invalid name compression pointer"

-- | Get a domain name, using sep1 as the separator between the 1st and 2nd
-- label.  Subsequent labels (and always the trailing label) are terminated
-- with a ".".
--
-- Note: the separator is required to be either \'.\' or \'\@\', or else
-- 'unparseLabel' needs to be modified to handle the new value.
--
-- Domain name compression pointers must always refer to a position that
-- precedes the start of the current domain name.  The starting offsets form a
-- strictly decreasing sequence, which prevents pointer loops.
--
getDomain' :: Word8 -> Int -> SGet ShortByteString
getDomain' sep1 ptrLimit = do
    pos <- parserPosition
    c <- getInt8
    let n = getValue c
    getdomain pos c n
  where
    -- Reprocess the same ShortByteString starting at the pointer
    -- target (offset).
    getPtr pos offset = do
        -- getInput takes the original entire input
        msg <- getInput
        let parser = skipNBytes offset >> getDomain' sep1 offset
        case runSGet parser msg of
            Left (DecodeError err) -> failSGet err
            Left err               -> fail $ show err
            Right o                -> do
                -- Cache only the presentation form decoding of domain names,
                -- mailboxes (e.g. SOA rname) are less frequently reused, and
                -- have a different presentation form, so must not share the
                -- same cache.
                when (sep1 == _period) $
                    pushDomain pos $ fst o
                return (fst o)

    getdomain pos c n
      | c == 0 = return "." -- Perhaps the root domain?
      | isPointer c = do
          d <- getInt8
          let offset = n * 256 + d
          when (offset >= ptrLimit) $
              failSGet "invalid name compression pointer"
          if sep1 /= _period
              then getPtr pos offset
              else popDomain offset >>= \case
                  Nothing -> getPtr pos offset
                  Just dm -> return dm
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return ""
      | otherwise = do
          hs <- unparseLabel sep1 <$> getNShortByteString n
          ds <- getDomain' _period ptrLimit
          let dom = case ds of -- avoid trailing ".."
                  "." -> hs <> "."
                  _   -> hs <> Short.singleton sep1 <> ds
          pushDomain pos dom
          return dom
    -- The length label is limited to 63.
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6

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
-- >>> unparseLabel _period "foo"
-- "foo"
-- >>> unparseLabel _period "foo.bar"
-- "foo\\.bar"
-- >>> unparseLabel _period "\x0aoo"
-- "\\010oo"
-- >>> unparseLabel _period "f\x7fo"
-- "f\\127o"
unparseLabel :: Word8 -> ShortByteString -> ShortByteString
unparseLabel sep label
  | isAllPlain label = label
  | otherwise        = toResult $ P.parse (labelUnparser sep mempty) label
  where
    isAllPlain = Short.all (isPlain sep)
    toResult (Just r, _) = r
    toResult _ = E.throw UnknownDNSError -- can't happen

labelUnparser :: Word8 -> Builder -> Parser Builder
labelUnparser sep bld0 = (P.eof $> bld0)
                     <|> (asis >>= \b -> labelUnparser sep (bld0 <> b))
                     <|> (esc  >>= \b -> labelUnparser sep (bld0 <> b))
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
isPlain sep w | w >= _del                  = False -- <DEL> + non-ASCII
              | w >  _backslash            = True  -- ']'..'_'..'a'..'z'..'~'
              | w >= _0  && w < _semicolon = True  -- '0'..'9'..':'
              | w >  _at && w < _backslash = True  -- 'A'..'Z'..'['
              | w <= _space                = False -- non-printables
              | isSpecial sep       w      = False -- one of the specials
              | otherwise                  = True  -- plain punctuation

----------------------------------------------------------------

shortToString :: ShortByteString -> String
shortToString = C8.unpack . Short.fromShort

----------------------------------------------------------------

-- |
--
-- >>> superDomains "www.example.com"
-- ["www.example.com","example.com","com"]
-- >>> superDomains "www.example.com."
-- ["www.example.com.","example.com.","com."]
superDomains :: Domain -> [Domain]
superDomains Domain{..} = map ciName ds
  where
    ds = domains origDomain

domains :: ShortByteString -> [ShortByteString]
domains ""  = []
domains "." = []
domains dom = loop dom
  where
    loop d = case parseLabel _period d of
      Nothing     -> []
      Just (_,"") -> [d]
      Just (_,xs) -> d : loop xs

-- |
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
