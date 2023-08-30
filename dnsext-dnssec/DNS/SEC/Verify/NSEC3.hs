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

type Logic a = (Domain -> [RangeProp]) -> TYPE -> [[RangeProp]] -> Maybe (Either String a)

getResult
    :: Logic a
    -> Maybe Domain
    -> [(NSEC3_Range, Hash)]
    -> Domain
    -> TYPE
    -> Either String a
getResult n3logic mayZone n3s qname qtype = do
    (zone, refine) <- n3RefineWithRanges n3s
    let guardZone z = when (z /= zone) $ Left $ "NSEC3.getResult: zone " ++ show z ++ " is not consistent for NSEC3 records"
    maybe (Right ()) guardZone mayZone
    let subs = zoneSubDomains qname zone
    when (null subs) $ Left $ "NSEC3.getResult: qname: " ++ show qname ++ " is not under zone: " ++ show zone
    let noEncloser = Left "NSEC3.getResult: no NSEC3 encloser"
    fromMaybe noEncloser $ n3logic refine qtype $ map refine subs

---

{- FOURMOLU_DISABLE -}
detect :: Logic NSEC3_Result
detect getPropSet qtype props =
    {- `stepNE` detects UnsignedDelegation case.
        Run this loop before `getNoData` to apply delegation
        for both UnsignedDelegation and NoData properties -}
    n3GetNonExistence (\_ _ ps -> stepNE ps)                getPropSet qtype props   <|>
    fmap N3R_NoData             <$> get_noData              getPropSet qtype props   <|>
    fmap N3R_WildcardExpansion  <$> get_wildcardExpansion   getPropSet qtype props
  where
    stepNE ps =
        fmap N3R_NameError           <$> step_nameError      getPropSet       ps  <|>
        fmap N3R_WildcardNoData      <$> step_wildcardNoData getPropSet qtype ps  <|>
        fmap N3R_UnsignedDelegation  <$> step_unsignedDelegation              ps
{- FOURMOLU_ENABLE -}

---

{- find NSEC3 records which covers or matches with qname or super names of qname,
   to recognize non-existence of domain or non-existence of RRset -}

get_nameError :: Logic NSEC3_NameError
get_nameError = n3GetNonExistence $ \getPropSet _ -> step_nameError getPropSet

{- find just qname matches -}
get_noData :: Logic NSEC3_NoData
get_noData _ _ [] = Just $ Left "NSEC3.NoData: no prop-set"
get_noData _ qtype (exists : _) = notElemBitmap <$> propMatch exists
  where
    notElemBitmap m@(Matches ((_, RD_NSEC3{..}), _))
        | qtype `elem` nsec3_types = Left $ "NSEC3.NoData: type bitmap has query type `" ++ show qtype ++ "`."
        | otherwise = Right $ n3_noData m

get_unsignedDelegation :: Logic NSEC3_UnsignedDelegation
get_unsignedDelegation = n3GetNonExistence $ \_ _ props -> step_unsignedDelegation props

{- loop for not-zipped prop-set list to check last zone-apex domain -}
get_wildcardExpansion :: Logic NSEC3_WildcardExpansion
get_wildcardExpansion _ _ = {- longest result -} msum . map step
  where
    step nexts = Right . n3_wildcardExpansion <$> propCover nexts

get_wildcardNoData :: Logic NSEC3_WildcardNoData
get_wildcardNoData = n3GetNonExistence step_wildcardNoData

---

n3GetNonExistence :: ((Domain -> [RangeProp]) -> TYPE -> RangeProps -> Maybe (Either String r)) -> Logic r
n3GetNonExistence neStep getPropSet qtype props = {- longest result -} msum $ map step pps
  where
    step = neStep getPropSet qtype
    {- reuse computed range-props for closest-name and next-closer-name -}
    pps = zip props (tail props)

step_nameError :: (Domain -> [RangeProp]) -> RangeProps -> Maybe (Either String NSEC3_NameError)
step_nameError getPropSet =
    n3StepNonExistence $ \nextCloser closest@(Matches (_, clname)) -> do
        let wildcardProps = getPropSet (fromString "*" <> clname)
        Right . n3_nameError closest nextCloser <$> propCover wildcardProps

step_unsignedDelegation :: RangeProps -> Maybe (Either String NSEC3_UnsignedDelegation)
step_unsignedDelegation =
    n3StepNonExistence $ \nextCloser@(Covers ((_, nextN3), _)) closest -> do
        let unsignedDelegation
                | OptOut `elem` nsec3_flags nextN3 = Right $ n3_unsignedDelegation closest nextCloser
                | otherwise = Left $ "NSEC3.UnsignedDelegation: No OptOut flag. Not NameErr, wildcard is not matched or covered."
        pure unsignedDelegation

step_wildcardNoData :: (Domain -> [RangeProp]) -> TYPE -> RangeProps -> Maybe (Either String NSEC3_WildcardNoData)
step_wildcardNoData getPropSet qtype =
    n3StepNonExistence $ \nextCloser closest@(Matches (_, clname)) -> do
        let wildcardProps = getPropSet (fromString "*" <> clname)
            notElemBitmap m@(Matches ((_, RD_NSEC3{..}), _))
                | qtype `elem` nsec3_types = Left $ "NSEC3.WildcardNoData: type bitmap has query type `" ++ show qtype ++ "`."
                | otherwise = Right $ n3_wildcardNoData closest nextCloser m
        notElemBitmap <$> propMatch wildcardProps

{- step to find non-existence of RRset.
   next-closer-name 'cover' for qname and closest-name 'match' for super-name are checked at the same time. -}
n3StepNonExistence
    :: (Covers NSEC3_Witness -> Matches NSEC3_Witness -> Maybe a)
    -> RangeProps
    -> Maybe a
n3StepNonExistence neHandler (nexts, closests) = do
    nextCloser <- propCover nexts
    closest <- propMatch closests
    neHandler nextCloser closest

---

newtype Matches a = Matches a deriving (Show)

newtype Covers a = Covers a deriving (Show)

n3_nameError
    :: Matches NSEC3_Witness
    -> Covers NSEC3_Witness
    -> Covers NSEC3_Witness
    -> NSEC3_NameError
n3_nameError (Matches closest) (Covers next) (Covers wildcard) =
    NSEC3_NameError closest next wildcard

n3_noData :: Matches NSEC3_Witness -> NSEC3_NoData
n3_noData (Matches closest) =
    NSEC3_NoData closest

n3_unsignedDelegation
    :: Matches NSEC3_Witness -> Covers NSEC3_Witness -> NSEC3_UnsignedDelegation
n3_unsignedDelegation (Matches closest) (Covers next) =
    NSEC3_UnsignedDelegation closest next

n3_wildcardExpansion :: Covers NSEC3_Witness -> NSEC3_WildcardExpansion
n3_wildcardExpansion (Covers next) =
    NSEC3_WildcardExpansion next

n3_wildcardNoData
    :: Matches NSEC3_Witness
    -> Covers NSEC3_Witness
    -> Matches NSEC3_Witness
    -> NSEC3_WildcardNoData
n3_wildcardNoData (Matches closest) (Covers next) (Matches wildcard) =
    NSEC3_WildcardNoData closest next wildcard

type RangeProp = RangeProp_ NSEC3_Witness

type RangeProps = ([RangeProp], [RangeProp])

type Hash = Domain -> Opaque

---

data RangeProp_ a
    = M (Matches a)
    | C (Covers a)
    deriving (Show)

propMatch :: [RangeProp] -> Maybe (Matches NSEC3_Witness)
propMatch xs = case [x | M x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

propCover :: [RangeProp] -> Maybe (Covers NSEC3_Witness)
propCover xs = case [x | C x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

---

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XTypeApplications

-- |
-- >>> n3Covers @Int 1 5 3
-- True
-- >>> n3Covers @Int 1 5 0
-- False
-- >>> n3Covers @Int 1 5 6
-- False
n3Covers :: Ord a => a -> a -> a -> Bool
n3Covers lower upper qv = lower < qv && qv < upper

-- |
--   In the last NSEC3 RR in the zone, lower limit and upper limit are rotated
--   * The lower limit, owner-name is the largest hash value in the zone
--   * The upper limit, next-domain is the smallest hash value in the zone
--
--   https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7
--   "The value of the Next Hashed Owner Name
--    field in the last NSEC3 RR in the zone is the same as the hashed
--    owner name of the first NSEC3 RR in the zone in hash order."
--
-- >>> n3CoversR @Int 5 1 0
-- True
-- >>> n3CoversR @Int 5 1 6
-- True
-- >>> n3CoversR @Int 5 1 3
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
        | length (filter fst results) > 1 = Left "NSEC3.n3RefineWithRanges: multiple rotated records found."
        | otherwise = Right props
      where
        props qname = [prop | (_, refine) <- results, Just prop <- [refine qname]]
        results =
            [ (rotated, result)
            | (owner, (rangeB32H@(_, RD_NSEC3{..}), hash)) <- ranges
            , let next = nsec3_next_hashed_owner_name {- binary hashed value, not base32hex -}
                  rotated = owner > next
                  refineWithRange cover qname
                    {- owner and next are decoded range, not base32hex -}
                    | hash qname == owner = Just $ M $ Matches (rangeB32H, qname)
                    | cover owner next (hash qname) = Just $ C $ Covers (rangeB32H, qname)
                    | otherwise = Nothing
                  result
                    | rotated = refineWithRange n3CoversR
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
