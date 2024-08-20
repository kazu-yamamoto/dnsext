{-# LANGUAGE MonadComprehensions #-}

module DNS.Iterative.Query.Helpers where

-- GHC packages
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import DNS.RRCache (Ranking)
import DNS.SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6), IPv4, IPv6)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Random
import DNS.Iterative.Query.Types
import DNS.Iterative.RootServers (rootServers)

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import DNS.Types

rrListWith
    :: TYPE
    -> (DNS.RData -> Maybe rd)
    -> Domain
    -> (rd -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
rrListWith typ fromRD dom = rrListWith' typ fromRD (== dom)

rrListWith'
    :: TYPE
    -> (DNS.RData -> Maybe rd)
    -> (Domain -> Bool)
    -> (rd -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
rrListWith' typ fromRD dpred h = foldr takeRR []
  where
    takeRR rr@ResourceRecord{rdata = rd} xs
        | dpred (rrname rr), rrtype rr == typ, Just ds <- fromRD rd = h ds rr : xs
    takeRR _ xs = xs

rrsigList :: Domain -> Domain -> TYPE -> [ResourceRecord] -> [(RD_RRSIG, TTL)]
rrsigList zone dom typ rrs = rrListWith RRSIG getSIGRD dom pair rrs
  where
    getSIGRD = sigrdZoneWith zone <=< sigrdTypeWith typ <=< DNS.fromRData
    pair rd rr = (rd, rrttl rr)

rrsetGoodSigs :: RRset -> [RD_RRSIG]
rrsetGoodSigs = mayVerifiedRRS [] [] (const []) id . rrsMayVerified

rrsetValid :: RRset -> Bool
rrsetValid = mayVerifiedRRS False False (const False) (const True) . rrsMayVerified

sigrdTypeWith :: TYPE -> RD_RRSIG -> Maybe RD_RRSIG
sigrdTypeWith sigType sigrd = guard (rrsig_type sigrd == sigType) $> sigrd

sigrdZoneWith :: Domain -> RD_RRSIG -> Maybe RD_RRSIG
sigrdZoneWith zone sigrd = guard (rrsig_zone sigrd == zone) $> sigrd

withSection
    :: (m -> ([ResourceRecord], Ranking))
    -> m
    -> ([ResourceRecord] -> Ranking -> a)
    -> a
withSection getRanked msg body = uncurry body $ getRanked msg

axList
    :: Bool
    -> (Domain -> Bool)
    -> (IP -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
axList disableV6NS pdom h = foldr takeAx []
  where
    takeAx rr@ResourceRecord{rrtype = A, rdata = rd} xs
        | pdom (rrname rr)
        , Just v4 <- DNS.rdataField rd DNS.a_ipv4 =
            h (IPv4 v4) rr : xs
    takeAx rr@ResourceRecord{rrtype = AAAA, rdata = rd} xs
        | not disableV6NS && pdom (rrname rr)
        , Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 =
            h (IPv6 v6) rr : xs
    takeAx _ xs = xs

rootHint :: Delegation
rootHint = withRootDelegation error id rootServers

withRootDelegation :: (String -> a) -> (Delegation -> a) -> ([ResourceRecord], [ResourceRecord]) -> a
withRootDelegation left right (ns, as) =
    maybe (left "withRootDelegation: bad configuration. NS list is empty?") (right . ($ [])) $
        findDelegation (rrListWith NS (`DNS.rdataField` DNS.ns_domain) (fromString ".") (,) ns) as

-- | The existence or non-existence of a Delegation is independent of the existence of [DS_RD].
-- >>> mkRR n ty rd = ResourceRecord n ty IN 3600000 rd
-- >>> ns = [mkRR "." NS $ rd_ns "m.root-servers.net."]
-- >>> as =[mkRR "m.root-servers.net." A $ rd_a "202.12.27.33", mkRR "m.root-servers.net." AAAA $ rd_aaaa "2001:dc3::35"]
-- >>> delegationNS . ($ []) <$> findDelegation (rrListWith NS (`DNS.rdataField` DNS.ns_domain) "." (,) ns) as
-- Just (DEwithAx "m.root-servers.net." (202.12.27.33 :| []) (2001:dc3::35 :| []) :| [])
findDelegation :: [(Domain, ResourceRecord)] -> [ResourceRecord] -> Maybe ([RD_DS] -> Delegation)
findDelegation = findDelegation' (\dom ents dss -> Delegation dom ents (FilledDS dss) [] FreshD)

{- FOURMOLU_DISABLE -}
findDelegation' :: (Domain -> NonEmpty DEntry -> a) -> [(Domain, ResourceRecord)] -> [ResourceRecord] -> Maybe a
findDelegation' k nsps adds = do
    ((_, rr), _) <- uncons nsps
    let nss = map fst nsps
    ents <- nonEmpty $ map (uncurry dentry) $ rrnamePairs (sort nss) addgroups
    {- only data from delegation source zone. get DNSKEY from destination zone -}
    Just $ k (rrname rr) ents
  where
    addgroups = groupBy ((==) `on` rrname) $ sortOn ((,) <$> rrname <*> rrtype) adds
    dentry d as = foldIPList' (DEonlyNS d) (DEwithA4 d) (DEwithA6 d) (DEwithAx d) ip4s ip6s
      where
        {- -----  -----  - domains are filtered by rrnamePairs, here does not check them -}
        ip4s = rrListWith' A    (`DNS.rdataField` DNS.a_ipv4)    (const True) const as
        ip6s = rrListWith' AAAA (`DNS.rdataField` DNS.aaaa_ipv6) (const True) const as
{- FOURMOLU_ENABLE -}

-- | pairing correspond rrname domain data
--
-- >>> let agroup n = [ ResourceRecord { rrname = n, rrtype = A, rrclass = IN, rrttl = 60, rdata = DNS.rd_a a } | a <- ["10.0.0.1", "10.0.0.2"] ]
-- >>> rrnamePairs ["s", "t", "u"] [agroup "s", agroup "t", agroup "u"] == [("s", agroup "s"), ("t", agroup "t"), ("u", agroup "u")]
-- True
-- >>> rrnamePairs ["t"] [agroup "s", agroup "t", agroup "u"] == [("t", agroup "t")]
-- True
-- >>> rrnamePairs ["s", "t", "u"] [agroup "t"] == [("s", []), ("t", agroup "t"), ("u", [])]
-- True
rrnamePairs :: [Domain] -> [[ResourceRecord]] -> [(Domain, [ResourceRecord])]
rrnamePairs = merge id (rrname . head) nullRR noName pair
  where
    nullRR n = ((n, []) :)
    noName _ = id
    pair n g = ((n, g) :)

{- FOURMOLU_DISABLE -}
foldDNSErrorToRCODE :: a -> (RCODE -> a) -> DNSError -> a
foldDNSErrorToRCODE n j e = case e of
    SequenceNumberMismatch  -> j FormatErr
    QuestionMismatch        -> j FormatErr
    RetryLimitExceeded      -> j ServFail
    TimeoutExpired          -> j ServFail
    UnexpectedRDATA         -> j FormatErr
    IllegalDomain           -> j ServFail
    FormatError             -> j FormatErr
    ServerFailure           -> j ServFail
    NameError               -> j NameErr
    NotImplemented          -> j NotImpl
    OperationRefused        -> j Refused
    BadOptRecord            -> j BadVers
    BadConfiguration        -> j ServFail
    NetworkFailure{}        -> j ServFail
    DecodeError{}           -> j FormatErr
    UnknownDNSError         -> j ServFail
    _                       -> n
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
foldIPList' :: a -> (NonEmpty IPv4 -> a) -> (NonEmpty IPv6 -> a)
            -> (NonEmpty IPv4 -> NonEmpty IPv6 -> a)
            -> [IPv4] -> [IPv6] -> a
foldIPList' n v4 v6 both v4list v6list = case v6list of
    []      -> list n v4' v4list
    i6:i6s  -> list (v6' i6 i6s) both' v4list
      where both' i4 i4s = both (i4 :| i4s) (i6 :| i6s)
  where
    v4' x xs = v4 $ x :| xs
    v6' x xs = v6 $ x :| xs

foldIPList :: a -> (NonEmpty IPv4 -> a) -> (NonEmpty IPv6 -> a)
           -> (NonEmpty IPv4 -> NonEmpty IPv6 -> a)
           -> [IP] -> a
foldIPList n v4 v6 both ips = foldIPList' n v4 v6 both v4list v6list
  where
    v4list = foldr takeV4 [] ips
    v6list = foldr takeV6 [] ips
    takeV4 (IPv4 i4) xs = i4 : xs
    takeV4  IPv6 {}  xs =      xs
    takeV6  IPv4 {}  xs =      xs
    takeV6 (IPv6 i6) xs = i6 : xs
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
dentryToRandomIP :: MonadIO m => Int -> Int -> Bool -> [DEntry] -> m [Address]
dentryToRandomIP entries addrs disableV6NS des = do
    acts  <- randomizedSelects entries actions             {- randomly select DEntry list -}
    es    <- map NE.toList <$> sequence acts               {- run randomly choice actions, ipv4 or ipv6  -}
    as    <- concat <$> mapM (randomizedSelects addrs) es  {- randomly select addresses from each DEntries -}
    pure $ unique as
  where
    actions = dentryIPsetChoices disableV6NS des
    unique = Set.toList . Set.fromList
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> v4 (i,_) = case i of { IPv4{} -> True  ; IPv6{} -> False }
-- >>> v6 (i,_) = case i of { IPv4{} -> False ; IPv6{} -> True  }
-- >>> expect1 p as = do { [a] <- pure as; is <- a; pure $ p $ NE.toList is }
--
-- >>> de4 = DEwithA4 "example." ("192.0.2.33" :| ["192.0.2.34"])
-- >>> expect1 (all v4) (dentryIPsetChoices False [de4])
-- True
-- >>> expect1 (all v4) (dentryIPsetChoices True  [de4])
-- True
--
-- >>> de6 = DEwithA6 "example." ("2001:db8::21" :| ["2001:db8::22"])
-- >>> expect1 (all v6) (dentryIPsetChoices False [de6])
-- True
-- >>> null             (dentryIPsetChoices True  [de6] :: [IO (NonEmpty Address)])
-- True
--
-- >>> de46 = DEwithAx "example." ("192.0.2.35" :| ["192.0.2.36"]) ("2001:db8::23" :| ["2001:db8::24"])
-- >>> expect1 ((||) <$> all v4 <*> all v6) (dentryIPsetChoices False [de46])
-- True
-- >>> expect1 (all v4)                     (dentryIPsetChoices True  [de46])
-- True
dentryIPsetChoices :: MonadIO m => Bool -> [DEntry] -> [m (NonEmpty Address)]
dentryIPsetChoices disableV6NS des = mapMaybe choose des
  where
    v4do53 i4s = [(IPv4 i, 53) | i <- i4s]
    v6do53 i6s = [(IPv6 i, 53) | i <- i6s]
    choose  DEonlyNS{}           = Nothing
    choose (DEwithA4 _ i4s)      = Just $ pure $ v4do53 i4s
    choose (DEwithA6 _ i6s)
        | disableV6NS            = Nothing
        | otherwise              = Just $ pure $ v6do53 i6s
    choose (DEwithAx _ i4s i6s)
        | disableV6NS            = Just $ pure $ v4do53 i4s
        | otherwise              = Just $ randomizedChoice (v4do53 i4s) (v6do53 i6s)
    choose (DEstubA4 i4s)        = Just $ pure [(IPv4 i, p) | (i, p) <- i4s]
    choose (DEstubA6 i6s)        = Just $ pure [(IPv6 i, p) | (i, p) <- i6s]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> de4 = DEwithA4 "example." ("192.0.2.37" :| ["192.0.2.38"])
-- >>> dentryIPnull False [de4]
-- False
-- >>> dentryIPnull True  [de4]
-- False
--
-- >>> de6 = DEwithA6 "example." ("2001:db8::25" :| ["2001:db8::26"])
-- >>> dentryIPnull False [de6]
-- False
-- >>> dentryIPnull True  [de6]
-- True
--
-- >>> de46 = DEwithAx "example." ("192.0.2.39" :| ["192.0.2.40"]) ("2001:db8::27" :| ["2001:db8::28"])
-- >>> dentryIPnull False [de46]
-- False
-- >>> dentryIPnull True  [de46]
-- False
dentryIPnull :: Bool -> [DEntry] -> Bool
dentryIPnull disableV6NS des = all ipNull des
  where
    ipNull  DEonlyNS{}            = True
    ipNull (DEwithA4 _ (_:|_))    = False  {- not null - with NonEmpty IPv4 -}
    ipNull  DEwithA6{}            = disableV6NS
    ipNull (DEwithAx _ (_:|_) _)  = False  {- not null - with NonEmpty IPv4 -}
    ipNull (DEstubA4 (_:|_))      = False
    ipNull (DEstubA6 (_:|_))      = disableV6NS
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
list1 :: b -> ([a] -> b) ->  [a] -> b
list1 nil _        []   =  nil
list1 _   cons xs@(_:_) =  cons xs

list :: b -> (a -> [a] -> b) ->  [a] -> b
list nil _     []    =  nil
list _   cons (x:xs) =  cons x xs
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- | generalized merge result of two sorted-lists
-- >>> let merge' = merge id id (\x -> ((x :: Int,0):)) (\y -> ((0,y):)) (\x y -> ((x,y):))
-- >>> merge' [] []
-- []
-- >>> merge' [1] []
-- [(1,0)]
-- >>> merge' [] [2]
-- [(0,2)]
-- >>> merge' [1,3,4,6] [1,2,5,6]
-- [(1,1),(0,2),(3,0),(4,0),(0,5),(6,6)]
merge :: Ord k
      => (a -> k) -> (b -> k)
      -> (a -> [c] -> [c]) -> (b -> [c] -> [c]) -> (a -> b -> [c] -> [c])
      -> [a] -> [b] -> [c]
merge keyx keyy consx consy cons = rec_
  where
    rec_       []            []       = []
    rec_       []           (ys:yss)  = consy ys   $ rec_  []   yss
    rec_      (xs:xss)       []       = consx xs   $ rec_  xss  []
    rec_ xss0@(xs:xss) yss0@(ys:yss)  = case compare (keyx xs) (keyy ys) of
        LT                           -> consx xs   $ rec_  xss  yss0
        GT                           -> consy ys   $ rec_  xss0 yss
        EQ                           -> cons xs ys $ rec_  xss  yss
{- FOURMOLU_ENABLE -}
