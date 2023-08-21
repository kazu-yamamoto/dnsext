{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSEC where

-- ghc packages
import Data.String (fromString)

-- dnsext-types
import DNS.Types hiding (qname)

-- this package
import DNS.SEC.Imports
import DNS.SEC.Types
import DNS.SEC.Verify.Types

getResult :: Logic -> Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_Result
getResult nlogic zone ranges qname qtype = do
    refine <- nsecRefineWithRanges ranges
    let qnames = refine qname
        coverwild = refine (fromString "*" <> zone)
        noEncloser = Left "NSEC3.getResult: no NSEC3 encloser"
    fromMaybe noEncloser $ nlogic (Zone zone) qtype qnames coverwild

newtype Zone = Zone Domain

type Logic = Zone -> TYPE -> [RangeProp] -> [RangeProp] -> Maybe (Either String NSEC_Result)

---

{- FOURMOLU_DISABLE -}
detect :: Logic
detect zone qtype qnames coverwild =
    get_wildcardNoData      zone qtype qnames coverwild  <|>
    get_nameError           zone qtype qnames coverwild  <|>
    get_unsignedDelegation  zone qtype qnames coverwild  <|>
    get_noData              zone qtype qnames coverwild  <|>
    get_wildcardExpansion   zone qtype qnames coverwild
{- FOURMOLU_ENABLE -}

---

get_nameError :: Logic
get_nameError _zone _qtype qnames coverwild = Right <$> (nsecR_NameError <$> propCover qnames <*> propCover coverwild)

get_noData :: Logic
get_noData _zone qtype qnames _coverwild = notElemBitmap <$> propMatch qnames
  where
    notElemBitmap m@(Matches ((_, RD_NSEC{..}), _))
        | qtype `elem` nsecTypes = Left $ "NSEC.verify: NoData: type bitmap has query type `" ++ show qtype ++ "`."
        | otherwise = Right $ nsecR_NoData m

get_unsignedDelegation :: Logic
get_unsignedDelegation (Zone zone) _qtype qnames _coverwild = do
    c@(Covers ((owner, RD_NSEC{..}), qn)) <- propCover qnames
    guard $ owner /= zone {- owner MUST be sub-level, not zone-top -}
    guard $ qn `isSubDomainOf` owner && NS `elem` nsecTypes {- super-domain is NS -}
    guard $ DS `notElem` nsecTypes {- not signed -}
    pure $ Right $ nsecR_UnsignedDelegation c

get_wildcardExpansion :: Logic
get_wildcardExpansion _zone _qtype qnames _coverwild = Right . nsecR_WildcardExpansion <$> propCover qnames

get_wildcardNoData :: Logic
get_wildcardNoData _zone qtype qnames _coverwild = do
    c <- propCover qnames
    let notElemBitmap w@(Wilds ((_, RD_NSEC{..}), _))
            | qtype `elem` nsecTypes = Left $ "NSEC.verify: WildcardNoData: type bitmap has query type `" ++ show qtype ++ "`."
            | otherwise = Right $ nsecR_WildcardNoData c w
    notElemBitmap <$> propWild qnames

---

newtype Matches a = Matches a deriving (Show)

newtype Covers a = Covers a deriving (Show)

newtype Wilds a = Wilds a deriving (Show)

rangeMatches :: NSEC_Range -> Matches NSEC_Witness
rangeMatches r@(owner, _nsec) = Matches (r, owner)

nsecR_NameError :: Covers NSEC_Witness -> Covers NSEC_Witness -> NSEC_Result
nsecR_NameError (Covers name) (Covers wildcard) =
    NSECResult_NameError name wildcard

nsecR_NoData :: Matches NSEC_Witness -> NSEC_Result
nsecR_NoData (Matches name) =
    NSECResult_NoData name

nsecR_UnsignedDelegation :: Covers NSEC_Witness -> NSEC_Result
nsecR_UnsignedDelegation (Covers name) =
    NSECResult_UnsignedDelegation name

nsecR_WildcardExpansion :: Covers NSEC_Witness -> NSEC_Result
nsecR_WildcardExpansion (Covers name) =
    NSECResult_WildcardExpansion name

nsecR_WildcardNoData
    :: Covers NSEC_Witness -> Wilds NSEC_Witness -> NSEC_Result
nsecR_WildcardNoData (Covers name) (Wilds wildcard) =
    NSECResult_WildcardNoData name wildcard

type RangeProp = RangeProp_ NSEC_Witness

---

data RangeProp_ a
    = M (Matches a)
    | C (Covers a)
    | W (Wilds a)
    deriving (Show)

propMatch :: [RangeProp] -> Maybe (Matches NSEC_Witness)
propMatch xs = case [x | M x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

propCover :: [RangeProp] -> Maybe (Covers NSEC_Witness)
propCover xs = case [x | C x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

propWild :: [RangeProp] -> Maybe (Wilds NSEC_Witness)
propWild xs = case [x | W x <- xs] of
    [] -> Nothing
    [x] -> Just x
    _ -> Nothing

---

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XTypeApplications

-- |
-- >>> nsecCovers @Int 1 5 3
-- True
-- >>> nsecCovers @Int 1 5 0
-- False
-- >>> nsecCovers @Int 1 5 6
-- False
nsecCovers :: Ord a => a -> a -> a -> Bool
nsecCovers lower upper qv = lower < qv && qv < upper

-- |
--   In the last NSEC RR, the next-domain is the zone apex,
--   so lower bound and upper boundaries are rotated.
--   The zone apex is the first NSEC RR in the canonical ordering of the zone.
--
--   https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.1
--   "The value of the Next Domain Name field in the last NSEC record in the zone is the name of
--    the zone apex (the owner name of the zone's SOA RR). This indicates that the owner name of
--    the NSEC RR is the last name in the canonical ordering of the zone."
--
-- >>> nsecCoversR @Int 5 1 0
-- True
-- >>> nsecCoversR @Int 5 1 6
-- True
-- >>> nsecCoversR @Int 5 1 3
-- False
nsecCoversR :: Ord a => a -> a -> a -> Bool
nsecCoversR lower upper qv = qv < upper || lower < qv

nsecRefineWithRanges :: [NSEC_Range] -> Either String (Domain -> [RangeProp])
nsecRefineWithRanges ranges
    | length (filter fst results) > 1 =
        Left "NSEC.nsecRangeRefines: multiple rorated records found."
    | otherwise = Right props
  where
    props qname = [prop | (_, refines) <- results, refine <- refines, Just prop <- [refine qname]]
    results =
        [ (rotated, [withRange, withWild])
        | range@(owner, RD_NSEC{..}) <- ranges
        , let next = nsecNextDomain
              rotated = owner > next
              refineWithRange cover qname
                | qname == owner = Just $ M $ Matches (range, qname)
                | cover owner next qname = Just $ C $ Covers (range, qname)
                | otherwise = Nothing
              withRange
                | rotated = refineWithRange nsecCoversR
                | otherwise = refineWithRange nsecCovers
              withWild qname = unconsLabels owner Nothing wildmatch
                where
                  wildmatch w wildsuper
                      | w == fromString "*" && qname `isSubDomainOf` wildsuper = Just $ W $ Wilds (range, qname)
                      | otherwise = Nothing
        ]
