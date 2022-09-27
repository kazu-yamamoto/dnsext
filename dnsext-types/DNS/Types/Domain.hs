{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Types.Domain (
    Domain
  , domainToByteString
  , byteStringToDomain
  , domainToText
  , textToDomain
  , putDomain
  , getDomain
  , Mailbox
  , mailboxToByteString
  , byteStringToMailbox
  , mailboxToText
  , textToMailbox
  , putMailbox
  , getMailbox
  ) where

import qualified Control.Exception as E
import qualified Data.Attoparsec.Text as P
import Data.Char (chr, ord, isDigit)
import Data.Functor (($>))
import Data.String
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import DNS.StateBinary
import DNS.Types.Error
import DNS.Types.Imports

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Data.Text

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
newtype Domain = Domain Text deriving (Eq, Ord)

instance Show Domain where
    show (Domain d) = T.unpack d

instance IsString Domain where
    fromString = Domain . T.pack

domainToByteString :: Domain -> ByteString
domainToByteString (Domain o) = T.encodeUtf8 o

byteStringToDomain :: ByteString -> Domain
byteStringToDomain = Domain . T.decodeUtf8

domainToText :: Domain -> Text
domainToText (Domain o) = o

textToDomain :: Text -> Domain
textToDomain = Domain

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
newtype Mailbox = Mailbox Text deriving (Eq, Ord)

instance Show Mailbox where
    show (Mailbox d) = T.unpack d

instance IsString Mailbox where
    fromString = Mailbox . T.pack

mailboxToByteString :: Mailbox -> ByteString
mailboxToByteString (Mailbox o) = T.encodeUtf8 o

byteStringToMailbox :: ByteString -> Mailbox
byteStringToMailbox = Mailbox . T.decodeUtf8

mailboxToText :: Mailbox -> Text
mailboxToText (Mailbox o) = o

textToMailbox :: Text -> Mailbox
textToMailbox = Mailbox

----------------------------------------------------------------

-- | Decode a domain name in A-label form to a leading label and a tail with
-- the remaining labels, unescaping backlashed chars and decimal triples along
-- the way. Any  U-label conversion belongs at the layer above this code.
--
-- >>> parseLabel '.' "abc\\.def.xyz"
-- Right ("abc.def","xyz")
-- >>> parseLabel '.' ".abc.def.xyz"
-- Left (DecodeError "invalid domain: .abc.def.xyz")
parseLabel :: Char -> Text -> Either DNSError (Text, Text)
parseLabel sep dom =
    if T.any (== '\\') dom
    then toResult $ P.parse (labelParser sep mempty) dom
    else check $ safeTail <$> T.break (== sep) dom
  where
    toResult (P.Partial c)  = toResult (c mempty)
    toResult (P.Done tl hd) = check (hd, tl)
    toResult _ = bottom
    safeTail bs | T.null bs = mempty
                | otherwise = T.tail bs
    check r@(hd, tl) | not (T.null hd) || T.null tl = Right r
                     | otherwise = bottom
    bottom = Left $ DecodeError $ "invalid domain: " ++ T.unpack dom

labelParser :: Char -> Text -> P.Parser Text
labelParser sep acc = do
    acc' <- mappend acc <$> P.option mempty simple
    labelEnd sep acc' <|> (escaped >>= labelParser sep . T.snoc acc')
  where
    simple = fst <$> P.match skipUnescaped
      where
        skipUnescaped = P.skipMany1 $ P.satisfy notSepOrBslash
        notSepOrBslash w = w /= sep && w /= '\\'

    escaped = do
        P.skip (== '\\')
        either decodeDec pure =<< P.eitherP digit P.anyChar
      where
        digit = ord <$> P.satisfy isDigit
        decodeDec d =
            safeChar =<< trigraph d <$> digit <*> digit
          where
            trigraph :: Int -> Int -> Int -> Int
            trigraph x y z = 100 * x + 10 * y + z

            safeChar :: Int -> P.Parser Char
            safeChar n | n > 255   = mzero
                       | otherwise = pure $ chr n

labelEnd :: Char -> Text -> P.Parser Text
labelEnd sep acc =
    P.satisfy (== sep) $> acc <|>
    P.endOfInput       $> acc

----------------------------------------------------------------

-- | Convert a wire-form label to presentation-form by escaping
-- the separator, special and non-printing characters.  For simple
-- labels with no bytes that require escaping we get back the input
-- Text asis with no copying or re-construction.
--
-- Note: the separator is required to be either \'.\' or \'\@\', but this
-- constraint is the caller's responsibility and is not checked here.
--
unparseLabel :: Char -> Text -> Text
unparseLabel sep label =
    if T.all (isPlain sep) label
    then label
    else toResult $ P.parse (labelUnparser sep mempty) label
  where
    toResult (P.Partial c) = toResult (c mempty)
    toResult (P.Done _ r) = r
    toResult _ = E.throw UnknownDNSError -- can't happen

labelUnparser :: Char -> Text -> P.Parser Text
labelUnparser sep acc = do
    acc' <- mappend acc <$> P.option mempty asis
    P.endOfInput $> acc' <|> (esc >>= labelUnparser sep . mappend acc')
  where
    -- Non-printables are escaped as decimal trigraphs, while printable
    -- specials just get a backslash prefix.
    esc = do
        w <- P.anyChar
        if w <= ' ' || w >= del
        then let (q100, r100) = ord w `divMod` 100
                 (q10, r10) = r100 `divMod` 10
              in pure $ T.pack [ '\\'
                               , chr (ord '0' + q100)
                               , chr (ord '0' + q10)
                               , chr (ord '0' + r10)
                               ]
        else pure $ T.pack [ '\\', w ]

    -- Runs of plain bytes are recognized as a single chunk, which is then
    -- returned as-is.
    asis = fmap fst $ P.match $ P.skipMany1 $ P.satisfy $ isPlain sep

-- | In the presentation form of DNS labels, these characters are escaped by
-- prepending a backlash. (They have special meaning in zone files). Whitespace
-- and other non-printable or non-ascii characters are encoded via "\DDD"
-- decimal escapes. The separator character is also quoted in each label. Note
-- that '@' is quoted even when not the separator.
escSpecials :: Text
escSpecials = "\"$();@\\"

-- | Is the given byte the separator or one of the specials?
isSpecial :: Char -> Char -> Bool
isSpecial sep w = w == sep || T.elem w escSpecials

-- | Is the given byte a plain byte that reqires no escaping. The tests are
-- ordered to succeed or fail quickly in the most common cases. The test
-- ranges assume the expected numeric values of the named special characters.
-- Note: the separator is assumed to be either '.' or '@' and so not matched by
-- any of the first three fast-path 'True' cases.
isPlain :: Char -> Char -> Bool
isPlain sep w | w >= del             = False -- <DEL> + non-ASCII
              | w > '\\'             = True  -- ']'..'_'..'a'..'z'..'~'
              | w >= '0' && w < ';'  = True  -- '0'..'9'..':'
              | w >  '@' && w < '\\' = True  -- 'A'..'Z'..'['
              | w <= ' '             = False -- non-printables
              | isSpecial sep w      = False -- one of the specials
              | otherwise            = True  -- plain punctuation

del :: Char
del = chr 127

rootDomain :: RawDomain
rootDomain = "."

putDomain :: Domain -> SPut
putDomain (Domain d) = putDomain' '.' d

putMailbox :: Mailbox -> SPut
putMailbox (Mailbox m) = putDomain' '@' m

putDomain' :: Char -> RawDomain -> SPut
putDomain' sep dom
    | T.null dom || dom == rootDomain = put8 0
    | otherwise = do
        mpos <- wsPop dom
        cur <- gets wsPosition
        case mpos of
            Just pos -> putPointer pos
            Nothing  -> do
                        -- Pointers are limited to 14-bits!
                        when (cur <= 0x3fff) $ wsPush dom cur
                        mconcat [ putPartialDomain hd
                                , putDomain' '.' tl
                                ]
  where
    -- Try with the preferred separator if present, else fall back to '.'.
    (hd, tl) = loop sep
      where
        loop w = case parseLabel w dom of
            Right p | w /= '.' && T.null (snd p) -> loop '.'
                    | otherwise -> p
            Left e -> E.throw e

putPointer :: Int -> SPut
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: RawDomain -> SPut
putPartialDomain = putText

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
getDomain = Domain <$> (getPosition >>= getDomain' '.')

getMailbox :: SGet Mailbox
getMailbox = Mailbox <$> (getPosition >>= getDomain' '@')

-- $
-- Pathological case: pointer embedded inside a label!  The pointer points
-- behind the start of the domain and is then absorbed into the initial label!
-- Though we don't IMHO have to support this, it is not manifestly illegal, and
-- does exercise the code in an interesting way.  Ugly as this is, it also
-- "works" the same in Perl's Net::DNS and reportedly in ISC's BIND.
--
-- >>> :{
-- let input = "\6\3foo\192\0\3bar\0"
--     parser = skipNBytes 1 >> getDomain' '.' 1
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
--     parser = skipNBytes 1 >> getDomain' '.' 1
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
getDomain' :: Char -> Int -> SGet Text
getDomain' sep1 ptrLimit = do
    pos <- getPosition
    c <- getInt8
    let n = getValue c
    getdomain pos c n
  where
    -- Reprocess the same Text starting at the pointer
    -- target (offset).
    getPtr pos offset = do
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
                when (sep1 == '.') $
                    push pos $ fst o
                return (fst o)

    getdomain pos c n
      | c == 0 = return "." -- Perhaps the root domain?
      | isPointer c = do
          d <- getInt8
          let offset = n * 256 + d
          when (offset >= ptrLimit) $
              failSGet "invalid name compression pointer"
          if sep1 /= '.'
              then getPtr pos offset
              else pop offset >>= \case
                  Nothing -> getPtr pos offset
                  Just o  -> return o
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return ""
      | otherwise = do
          hs <- unparseLabel sep1 <$> getNText n
          ds <- getDomain' '.' ptrLimit
          let dom = case ds of -- avoid trailing ".."
                  "." -> hs <> "."
                  _   -> hs <> T.singleton sep1 <> ds
          push pos dom
          return dom
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6

----------------------------------------------------------------
