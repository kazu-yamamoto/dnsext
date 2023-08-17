{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSEC3 where

-- ghc packages
import Data.ByteString.Short (fromShort)
import Data.String (fromString)

-- dnsext-types
import DNS.Types hiding (qname)
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.SEC.Flags (NSEC3_Flag (OptOut))
import DNS.SEC.Imports
import DNS.SEC.Types
import DNS.SEC.Verify.Types

type Logic = (Domain -> [RangeProp]) -> Domain -> TYPE -> [[RangeProp]] -> Maybe (Either String NSEC3_Result)

getResult
    :: Logic
    -> [(NSEC3_Range, Hash)]
    -> Domain
    -> TYPE
    -> Either String NSEC3_Result
getResult n3logic n3s qname qtype = do
    (zone, refine) <- n3RefineWithRanges n3s
    let subs = zoneSubDomains qname zone
        propSets = map refine subs
        noEncloser = Left "NSEC3.getResult: no NSEC3 encloser"
    when (null subs) $ Left $ "NSEC3.getResult: qname: " ++ show qname ++ " is not under zone: " ++ show zone
    fromMaybe noEncloser $ n3logic refine qname qtype propSets

---

{- FOURMOLU_DISABLE -}
detect :: Logic
detect getPropSet qname qtype props =
    {- `stepNE` detects UnsignedDelegation case.
        Run this loop before `getNoData` to apply delegation
        for both UnsignedDelegation and NoData properties -}
    msum (map stepNE pps)                                  <|>
    get_noData              getPropSet qname qtype props   <|>
    get_wildcardExpansion   getPropSet qname qtype props
  where
    stepNE ps =
        step_nameError getPropSet ps             <|>
        step_wildcardNoData getPropSet qtype ps  <|>
        step_unsignedDelegation ps
    pps = zip props (tail props)  {- reuse computed range-props for closest-name and next-closer-name -}
{- FOURMOLU_ENABLE -}

---

{- find NSEC3 records which covers or matches with qname or super names of qname,
   to recognize non-existence of domain or non-existence of RRset -}

get_nameError :: Logic
get_nameError getPropSet _qname _qtype props = msum $ map step pps
  where
    step = step_nameError getPropSet
    {- reuse computed range-props for closest-name and next-closer-name -}
    pps = zip props (tail props)

{- find just qname matches -}
get_noData :: Logic
get_noData _ _ _ [] = Just $ Left "NSEC3.get_noData: no prop-set"
get_noData _ _ qtype (exists : _) = notElemBitmap <$> propMatches1 exists
  where
    notElemBitmap m@(Matches ((_, RD_NSEC3{..}), _))
        | qtype `elem` nsec3_types = Left $ "NSEC3.n3Get_noData: type bitmap has query type `" ++ show qtype ++ "`."
        | otherwise = Right $ n3r_noData m

get_unsignedDelegation :: Logic
get_unsignedDelegation _ _ _ props = msum $ map step pps
  where
    step = step_unsignedDelegation
    {- reuse computed range-props for closest-name and next-closer-name -}
    pps = zip props (tail props)

get_wildcardExpansion :: Logic
get_wildcardExpansion _ _ _ = {- first result -} msum . map step
  where
    step :: [RangeProp] -> Maybe (Either String NSEC3_Result)
    step nexts = Right . n3r_wildcardExpansion <$> propCovers1 nexts

get_wildcardNoData :: Logic
get_wildcardNoData getPropSet _qname qtype props = msum $ map step pps
  where
    step = step_wildcardNoData getPropSet qtype
    {- reuse computed range-props for closest-name and next-closer-name -}
    pps = zip props (tail props)

---

step_nameError :: (Domain -> [RangeProp]) -> RangeProps -> Maybe (Either String NSEC3_Result)
step_nameError getPropSet =
    n3StepNonExistence $ \closest nextCloser clname _nextN3 -> do
        let wildcardProps = getPropSet (fromString "*" <> clname)
        Right . n3r_nameError closest nextCloser <$> propCovers1 wildcardProps

step_unsignedDelegation :: RangeProps -> Maybe (Either String NSEC3_Result)
step_unsignedDelegation =
    n3StepNonExistence $ \closest nextCloser _clname nextN3 -> do
        let unsignedDelegation
                | OptOut `elem` nsec3_flags nextN3 = Right $ n3r_unsignedDelegation closest nextCloser
                | otherwise = Left $ "NSEC3.get_unsignedDelegation: wildcard name is not matched or covered."
        pure unsignedDelegation

step_wildcardNoData :: (Domain -> [RangeProp]) -> TYPE -> RangeProps -> Maybe (Either String NSEC3_Result)
step_wildcardNoData getPropSet qtype =
    n3StepNonExistence $ \closest nextCloser clname _nextN3 -> do
        let wildcardProps = getPropSet (fromString "*" <> clname)
            notElemBitmap m@(Matches ((_, RD_NSEC3{..}), _))
                | qtype `elem` nsec3_types = Left $ "NSEC3.get_wildcardNoData: type bitmap has query type `" ++ show qtype ++ "`."
                | otherwise = Right $ n3r_wildcardNoData closest nextCloser m
        notElemBitmap <$> propMatches1 wildcardProps

{- step to find non-existence of RRset.
   next-closer-name 'cover' for qname and closest-name 'match' for super-name are checked at the same time. -}
n3StepNonExistence
    :: (Matches NSEC3_Witness -> Covers NSEC3_Witness -> Domain -> RD_NSEC3 -> Maybe a)
    -> RangeProps
    -> Maybe a
n3StepNonExistence neHandler (nexts, closests) = do
    nextCloser@(Covers ((_, nextN3), _)) <- propCovers1 nexts
    closest@(Matches (_, clname)) <- propMatches1 closests
    neHandler closest nextCloser clname nextN3

---

newtype Matches a = Matches a deriving (Show)

newtype Covers a = Covers a deriving (Show)

n3r_nameError
    :: Matches NSEC3_Witness
    -> Covers NSEC3_Witness
    -> Covers NSEC3_Witness
    -> NSEC3_Result
n3r_nameError (Matches closest) (Covers next) (Covers wildcard) =
    N3Result_NameError closest next wildcard

n3r_noData :: Matches NSEC3_Witness -> NSEC3_Result
n3r_noData (Matches closest) =
    N3Result_NoData closest

n3r_unsignedDelegation
    :: Matches NSEC3_Witness -> Covers NSEC3_Witness -> NSEC3_Result
n3r_unsignedDelegation (Matches closest) (Covers next) =
    N3Result_UnsignedDelegation closest next

n3r_wildcardExpansion :: Covers NSEC3_Witness -> NSEC3_Result
n3r_wildcardExpansion (Covers next) =
    N3Result_WildcardExpansion next

n3r_wildcardNoData
    :: Matches NSEC3_Witness
    -> Covers NSEC3_Witness
    -> Matches NSEC3_Witness
    -> NSEC3_Result
n3r_wildcardNoData (Matches closest) (Covers next) (Matches wildcard) =
    N3Result_WildcardNoData closest next wildcard

type RangeProp = RangeProp_ NSEC3_Witness

type RangeProps = ([RangeProp], [RangeProp])

type Hash = Domain -> Opaque

---

data RangeProp_ a
    = M (Matches a)
    | C (Covers a)
    deriving (Show)

propMatches1 :: [RangeProp] -> Maybe (Matches NSEC3_Witness)
propMatches1 xs = case [x | M x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

propCovers1 :: [RangeProp] -> Maybe (Covers NSEC3_Witness)
propCovers1 xs = case [x | C x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

---

-- $setup
-- >>> :set -XOverloadedStrings

-- |
-- >>> n3Covers 1 5 3
-- True
-- >>> n3Covers 1 5 0
-- False
-- >>> n3Covers 1 5 6
-- False
n3Covers :: Ord a => a -> a -> a -> Bool
n3Covers lower upper qv = lower < qv && qv < upper

-- |
--   https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7
--   "The value of the Next Hashed Owner Name
--    field in the last NSEC3 RR in the zone is the same as the hashed
--    owner name of the first NSEC3 RR in the zone in hash order."
--
-- >>> n3CoversR 5 1 0
-- True
-- >>> n3CoversR 5 1 6
-- True
-- >>> n3CoversR 5 1 3
-- False
n3CoversR :: Ord a => a -> a -> a -> Bool
n3CoversR lower upper qv = qv < upper || lower < qv

{- get func to compute 'match' or 'cover' with ranges from NSEC3 record-set -}
n3RefineWithRanges
    :: [(NSEC3_Range, Hash)]
    -> Either String (Domain, Domain -> [RangeProp])
n3RefineWithRanges ranges0 = do
    (((owner1, _), _), _) <- maybe (Left "NSEC3.n3RefineWithRanges: no NSEC3 records") Right $ uncons ranges0
    zname <- unconsLabels owner1 (Left "NSEC3.n3RefineWithRanges: no zone name") (const Right)

    let rs =
            [ (ownerBytes, r)
            | r@((rrn, RD_NSEC3{..}), _) <- ranges0
            , nsec3_flags `elem` [[], [OptOut]]
            , {- https://datatracker.ietf.org/doc/html/rfc5155#section-8.2
                 "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one." -}
            (owner32h, parent) <- unconsLabels rrn [] (\x y -> [(x, y)])
            , parent == zname
            , ownerBytes <- decodeBase32 owner32h
            ]
    (,) zname <$> takeRefines rs
  where
    decodeBase32 :: ShortByteString -> [Opaque]
    decodeBase32 part = either (const []) (: []) $ Opaque.fromBase32Hex $ fromShort part

    takeRefines :: [(Opaque, (NSEC3_Range, Hash))] -> Either String (Domain -> [RangeProp])
    takeRefines ranges
        | length (filter fst results) > 1 = Left "NSEC3.n3RefineWithRanges: multiple rounded records found."
        | otherwise = Right props
      where
        props qname = [prop | (_, refine) <- results, Just prop <- [refine qname]]
        results =
            [ (rounded, result)
            | (owner, (rangeB32H@(_, RD_NSEC3{..}), hash)) <- ranges
            , let next = nsec3_next_hashed_owner_name {- binary hashed value, not base32hex -}
                  rounded = owner > next
                  refineWithRange cover qname
                    {- owner and next are decoded range, not base32hex -}
                    | hash qname == owner = Just $ M $ Matches (rangeB32H, qname)
                    | cover owner next (hash qname) = Just $ C $ Covers (rangeB32H, qname)
                    | otherwise = Nothing
                  result
                    | rounded = refineWithRange n3CoversR
                    | otherwise = refineWithRange n3Covers
                    {- base32hex does not change hash ordering. https://datatracker.ietf.org/doc/html/rfc5155#section-1.3
                       "Terminology: Hash order:
                        Note that this order is the same as the canonical DNS name order specified in [RFC4034],
                        when the hashed owner names are in base32, encoded with an Extended Hex Alphabet [RFC4648]." -}
            ]

-- |
-- >>> zoneSubDomains "a.b.c.d.e." "c.d.e."
-- ["a.b.c.d.e.","b.c.d.e.","c.d.e."]
-- >>> zoneSubDomains "example.com." "."
-- ["example.com.","com.","."]
-- >>> zoneSubDomains "example.com." "a.example.com."
-- []
zoneSubDomains :: Domain -> Domain -> [Domain]
zoneSubDomains domain zone
    | domain `isSubDomainOf` zone = takeWhile (/= zone) (superDomains domain ++ [fromString "."]) ++ [zone]
    | otherwise = []
