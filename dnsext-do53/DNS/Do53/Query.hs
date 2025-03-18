{-# LANGUAGE CPP #-}

module DNS.Do53.Query (
    QueryControls (..),
    HeaderControls (..),
    EdnsControls (..),
    FlagOp (..),
    rdFlag,
    adFlag,
    cdFlag,
    doFlag,
    ednsEnabled,
    ednsSetVersion,
    ednsSetUdpSize,
    ednsSetOptions,
    queryControls,
    modifyQuery,
    encodeQuery,
    ODataOp (..),
)
where

import DNS.Do53.Imports
import DNS.Types
import DNS.Types.Encode
import qualified Data.Semigroup as Sem

----------------------------------------------------------------

-- | Query controls form a 'Monoid', as with function composition, the
-- left-most value has the last say.  The 'Monoid' is generated by two sets of
-- combinators, one that controls query-related DNS header flags, and another
-- that controls EDNS features.
--
-- The header flag controls are: 'rdFlag', 'adFlag' and 'cdFlag'.
--
-- The EDNS feature controls are: 'doFlag', 'ednsEnabled', 'ednsSetVersion',
-- 'ednsSetUdpSize' and 'ednsSetOptions'.  When EDNS is disabled, all the other
-- EDNS-related controls have no effect.
--
-- __Example:__ Disable DNSSEC checking on the server, and request signatures and
-- NSEC records, perhaps for your own independent validation.  The UDP buffer
-- size is set large, for use with a local loopback nameserver on the same host.
--
-- >>> :{
-- mconcat [ adFlag FlagClear
--         , cdFlag FlagSet
--         , doFlag FlagSet
--         , ednsSetUdpSize (Just 8192) -- IPv4 loopback server?
--         ]
-- :}
-- ad:0,cd:1,edns.udpsize:8192,edns.dobit:1
--
-- __Example:__ Use EDNS version 1 (yet to be specified), request nameserver
-- ids from the server, and indicate a client subnet of "192.0.2.1/24".
--
-- >>> :set -XOverloadedStrings
-- >>> let emptyNSID = ""
-- >>> let msk = 24
-- >>> let ipaddr = read "192.0.2.1"
-- >>> :{
-- mconcat [ ednsSetVersion (Just 1)
--         , ednsSetOptions (ODataAdd [od_nsid emptyNSID])
--         , ednsSetOptions (ODataAdd [od_clientSubnet msk 0 ipaddr])
--         ]
-- :}
-- edns.version:1,edns.options:[NSID,ClientSubnet]
data QueryControls = QueryControls
    { qctlHeader :: HeaderControls
    , qctlEdns :: EdnsControls
    }
    deriving (Eq)

instance Sem.Semigroup QueryControls where
    (QueryControls fl1 ex1) <> (QueryControls fl2 ex2) =
        QueryControls (fl1 <> fl2) (ex1 <> ex2)

instance Monoid QueryControls where
    mempty = QueryControls mempty mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show QueryControls where
    show (QueryControls fl ex) = _showOpts [show fl, show ex]

----------------------------------------------------------------

-- | Generator of 'QueryControls' that adjusts the RD (Recursion Desired) bit.
--
-- >>> rdFlag FlagClear
-- rd:0
rdFlag :: FlagOp -> QueryControls
rdFlag rd = mempty{qctlHeader = mempty{rdBit = rd}}

-- | Generator of 'QueryControls' that adjusts the AD (Authentic Data) bit.
--
-- >>> adFlag FlagSet
-- ad:1
adFlag :: FlagOp -> QueryControls
adFlag ad = mempty{qctlHeader = mempty{adBit = ad}}

-- | Generator of 'QueryControls' that adjusts the CD (Checking Disabled) bit.
--
-- >>> cdFlag FlagSet
-- cd:1
cdFlag :: FlagOp -> QueryControls
cdFlag cd = mempty{qctlHeader = mempty{cdBit = cd}}

-- | Generator of 'QueryControls' that enables or disables EDNS support.
--   When EDNS is disabled, the rest of the 'EDNS' controls are ignored.
--
-- >>> ednsHeader $ modifyQuery (ednsEnabled FlagClear <> doFlag FlagSet) defaultQuery
-- NoEDNS
ednsEnabled :: FlagOp -> QueryControls
ednsEnabled en = mempty{qctlEdns = mempty{extEn = en}}

-- | Generator of 'QueryControls' that adjusts the 'EDNS' version.
-- A value of 'Nothing' makes no changes, while 'Just' @v@ sets
-- the EDNS version to @v@.
--
-- >>> ednsSetVersion (Just 1)
-- edns.version:1
ednsSetVersion :: Maybe Word8 -> QueryControls
ednsSetVersion vn = mempty{qctlEdns = mempty{extVn = vn}}

-- | Generator of 'QueryControls' that adjusts the 'EDNS' UDP buffer size.
-- A value of 'Nothing' makes no changes, while 'Just' @n@ sets the EDNS UDP
-- buffer size to @n@.
--
-- >>> ednsSetUdpSize (Just 2048)
-- edns.udpsize:2048
ednsSetUdpSize :: Maybe Word16 -> QueryControls
ednsSetUdpSize sz = mempty{qctlEdns = mempty{extSz = sz}}

-- | Generator of 'QueryControls' that adjusts the 'EDNS' DO (DNSSEC OK) bit.
--
-- >>> doFlag FlagSet
-- edns.dobit:1
doFlag :: FlagOp -> QueryControls
doFlag d0 = mempty{qctlEdns = mempty{extDO = d0}}

-- | Generator of 'QueryControls' that adjusts the list of 'EDNS' options.
--
-- >>> :set -XOverloadedStrings
-- >>> ednsSetOptions (ODataAdd [od_nsid ""])
-- edns.options:[NSID]
ednsSetOptions :: ODataOp -> QueryControls
ednsSetOptions od = mempty{qctlEdns = mempty{extOd = od}}

----------------------------------------------------------------

-- | Control over query-related DNS header flags. As with function composition,
-- the left-most value has the last say.
data HeaderControls = HeaderControls
    { rdBit :: FlagOp
    , adBit :: FlagOp
    , cdBit :: FlagOp
    }
    deriving (Eq)

instance Sem.Semigroup HeaderControls where
    (HeaderControls rd1 ad1 cd1) <> (HeaderControls rd2 ad2 cd2) =
        HeaderControls (rd1 <> rd2) (ad1 <> ad2) (cd1 <> cd2)

instance Monoid HeaderControls where
    mempty = HeaderControls FlagKeep FlagKeep FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show HeaderControls where
    show (HeaderControls rd ad cd) =
        _showOpts
            [ _showFlag "rd" rd
            , _showFlag "ad" ad
            , _showFlag "cd" cd
            ]

----------------------------------------------------------------

-- | The default EDNS Option list is empty.  We define two operations, one to
-- prepend a list of options, and another to set a specific list of options.
data ODataOp
    = -- | Add the specified options to the list.
      ODataAdd [OData]
    | -- | Set the option list as specified.
      ODataSet [OData]
    deriving (Eq)

-- | Since any given option code can appear at most once in the list, we
-- de-duplicate by the OPTION CODE when combining lists.
_odataDedup :: ODataOp -> [OData]
_odataDedup op =
    nubBy ((==) `on` odataToOptCode) $
        case op of
            ODataAdd os -> os
            ODataSet os -> os

-- $
-- Test associativity of the OData semigroup operation:
--
-- >>> import Data.IP
-- >>> let ip1 = IPv4 $ read "127.0.0.0"
-- >>> let ip2 = IPv4 $ read "192.0.2.0"
-- >>> let cs1 = od_clientSubnet 8 0 ip1
-- >>> let cs2 = od_clientSubnet 24 0 ip2
-- >>> let cs3 = od_ecsGeneric 0 24 0 "foo"
-- >>> let nsid = od_nsid ""
-- >>> let ops1 = [ODataAdd [cs1], ODataAdd [cs2]]
-- >>> let ops2 = [ODataSet [], ODataSet [cs3], ODataSet [nsid]]
-- >>> let ops = ops1 ++ ops2
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True

instance Sem.Semigroup ODataOp where
    ODataAdd as <> ODataAdd bs = ODataAdd $ as ++ bs
    ODataAdd as <> ODataSet bs = ODataSet $ as ++ bs
    ODataSet as <> _ = ODataSet as

instance Monoid ODataOp where
    mempty = ODataAdd []
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

----------------------------------------------------------------

-- | EDNS query controls.  When EDNS is disabled via @ednsEnabled FlagClear@,
-- all the other EDNS-related overrides have no effect.
--
-- >>> ednsHeader $ modifyQuery (ednsEnabled FlagClear <> doFlag FlagSet) defaultQuery
-- NoEDNS
data EdnsControls = EdnsControls
    { extEn :: FlagOp
    -- ^ Enabled
    , extVn :: Maybe Word8
    -- ^ Version
    , extSz :: Maybe Word16
    -- ^ UDP Size
    , extDO :: FlagOp
    -- ^ DNSSEC OK (DO) bit
    , extOd :: ODataOp
    -- ^ EDNS option list tweaks
    }
    deriving (Eq)

instance Sem.Semigroup EdnsControls where
    (EdnsControls en1 vn1 sz1 do1 od1) <> (EdnsControls en2 vn2 sz2 do2 od2) =
        EdnsControls
            (en1 <> en2)
            (vn1 <|> vn2)
            (sz1 <|> sz2)
            (do1 <> do2)
            (od1 <> od2)

instance Monoid EdnsControls where
    mempty = EdnsControls FlagKeep Nothing Nothing FlagKeep mempty
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

instance Show EdnsControls where
    show (EdnsControls en vn sz d0 od) =
        _showOpts
            [ _showFlag "edns.enabled" en
            , _showWord "edns.version" vn
            , _showWord "edns.udpsize" sz
            , _showFlag "edns.dobit" d0
            , _showOdOp "edns.options" $
                map (show . odataToOptCode) $
                    _odataDedup od
            ]
      where
        _showWord :: Show a => String -> Maybe a -> String
        _showWord nm w = maybe _skipDefault (\s -> nm ++ ":" ++ show s) w

        _showOdOp :: String -> [String] -> String
        _showOdOp nm os = case os of
            [] -> ""
            _ -> nm ++ ":[" ++ intercalate "," os ++ "]"

----------------------------------------------------------------

-- | Boolean flag operations. These form a 'Monoid'.  When combined via
-- `mappend`, as with function composition, the left-most value has
-- the last say.
--
-- >>> mempty :: FlagOp
-- FlagKeep
-- >>> FlagSet <> mempty
-- FlagSet
-- >>> FlagClear <> FlagSet <> mempty
-- FlagClear
-- >>> FlagReset <> FlagClear <> FlagSet <> mempty
-- FlagReset
data FlagOp
    = -- | Set the flag to 1
      FlagSet
    | -- | Clear the flag to 0
      FlagClear
    | -- | Reset the flag to its default value
      FlagReset
    | -- | Leave the flag unchanged
      FlagKeep
    deriving (Eq, Show)

-- $
-- Test associativity of the semigroup operation:
--
-- >>> let ops = [FlagSet, FlagClear, FlagReset, FlagKeep]
-- >>> foldl (&&) True [(a<>b)<>c == a<>(b<>c) | a <- ops, b <- ops, c <- ops]
-- True

instance Sem.Semigroup FlagOp where
    FlagKeep <> op = op
    op <> _ = op

instance Monoid FlagOp where
    mempty = FlagKeep
#if !(MIN_VERSION_base(4,11,0))
    -- this is redundant starting with base-4.11 / GHC 8.4
    -- if you want to avoid CPP, you can define `mappend = (<>)` unconditionally
    mappend = (Sem.<>)
#endif

-- | We don't show options left at their default value.
_skipDefault :: String
_skipDefault = ""

-- | Show non-default flag values
_showFlag :: String -> FlagOp -> String
_showFlag nm FlagSet = nm ++ ":1"
_showFlag nm FlagClear = nm ++ ":0"
_showFlag _ FlagReset = _skipDefault
_showFlag _ FlagKeep = _skipDefault

-- | Combine a list of options for display, skipping default values
_showOpts :: [String] -> String
_showOpts os = intercalate "," $ filter (/= _skipDefault) os

----------------------------------------------------------------

-- | The encoded 'DNSMessage' has the specified request ID.  The default values
-- of the RD, AD, CD and DO flag bits, as well as various EDNS features, can be
-- adjusted via the 'QueryControls' parameter.
--
-- The caller is responsible for generating the ID via a securely seeded
-- CSPRNG.
encodeQuery
    :: Identifier
    -- ^ Crypto random request id
    -> Question
    -- ^ Query name and type
    -> QueryControls
    -- ^ Query flag and EDNS overrides
    -> ByteString
encodeQuery idt q ctls = encode $ modifyQuery ctls $ makeQuery idt q

modifyQuery
    :: QueryControls
    -- ^ Flag and EDNS overrides
    -> DNSMessage
    -> DNSMessage
modifyQuery ctls query = queryControls (\mf eh -> query{ flags = mf (flags query), ednsHeader = eh}) ctls

queryControls
    :: ((DNSFlags -> DNSFlags) -> EDNSheader -> a)
    -> QueryControls
    -> a
queryControls h ctls = h (queryDNSFlags hctls) (queryEdns ehctls)
  where
    hctls = qctlHeader ctls
    ehctls = qctlEdns ctls

    -- \| Apply the given 'FlagOp' to a default boolean value to produce the final
    -- setting.
    applyFlag :: FlagOp -> Bool -> Bool
    applyFlag FlagSet _ = True
    applyFlag FlagClear _ = False
    applyFlag _ v = v

    -- \| Construct a list of 0 or 1 EDNS OPT RRs based on EdnsControls setting.
    queryEdns :: EdnsControls -> EDNSheader
    queryEdns (EdnsControls en vn sz d0 od) =
        let d = defaultEDNS -- fixme: ednsHeader query?
         in if en == FlagClear
                then NoEDNS
                else
                    EDNSheader $
                        d
                            { ednsVersion = fromMaybe (ednsVersion d) vn
                            , ednsUdpSize = fromMaybe (ednsUdpSize d) sz
                            , ednsDnssecOk = applyFlag d0 (ednsDnssecOk d)
                            , ednsOptions = _odataDedup od
                            }

    -- \| Apply all the query flag, returning the
    -- resulting 'DNSFlags' suitable for making queries with the requested flag
    -- settings.  This is only needed if you're creating your own 'DNSMessage',
    -- the 'DNS.Do53.lookupRawCtl' function takes a 'QueryControls'
    -- argument and handles this conversion internally.
    --
    -- Default overrides can be specified in the resolver configuration by setting
    -- the 'DNS.Do53.resolvQueryControls' field of the
    -- 'DNS.Do53.ResolveConf'.
    -- These then apply to lookups via
    -- resolvers based on the resulting configuration, with the exception of
    -- 'DNS.Do53.lookupRawCtl' which takes an additional
    -- 'QueryControls' argument to augment the default overrides.
    queryDNSFlags :: HeaderControls -> DNSFlags -> DNSFlags
    queryDNSFlags (HeaderControls rd ad cd) d =
        d
            { recDesired = applyFlag rd $ recDesired d
            , authenData = applyFlag ad $ authenData d
            , chkDisable = applyFlag cd $ chkDisable d
            }
