{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSEC where

-- dnsext-types

-- this package
import DNS.SEC.Imports
import DNS.SEC.Types
import DNS.SEC.Verify.Types
import DNS.Types hiding (qname)
import Data.String (fromString)

verify :: Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_Result
verify zone ranges qname qtype = do
    refines <- nsecRangeRefines ranges
    findEncloser refines
  where
    findEncloser refines =
        maybe (Left "NSEC.verify: no NSEC encloser") id $
            getWildcardNoData
                <|> getNameError
                <|> getUnsignedDelegation
                <|> getNoData
                <|> getWildcardExpansion
      where
        getNameError = Right <$> (nsecR_NameError <$> cover qnames <*> cover wildcards)
          where
            wildcards = getProps (fromString "*" <> zone)

        getNoData = notElemBitmap <$> match qnames
          where
            notElemBitmap m@(Matches ((_, RD_NSEC{..}), _))
                | qtype `elem` nsecTypes =
                    Left $ "NSEC.verify: NoData: type bitmap has query type `" ++ show qtype ++ "`."
                | otherwise = Right $ nsecR_NoData m

        getUnsignedDelegation = do
            c@(Covers ((owner, RD_NSEC{..}), qn)) <- cover qnames
            guard $ owner /= zone {- owner MUST be sub-level, not zone-top -}
            guard $ qn `isSubDomainOf` owner && NS `elem` nsecTypes {- super-domain is NS -}
            guard $ DS `notElem` nsecTypes {- not signed -}
            return $ Right $ nsecR_UnsignedDelegation c

        getWildcardExpansion = Right . nsecR_WildcardExpansion <$> cover qnames

        getWildcardNoData = do
            c <- cover qnames
            let notElemBitmap w@(Wilds ((_, RD_NSEC{..}), _))
                    | qtype `elem` nsecTypes =
                        Left $
                            "NSEC.verify: WildcardNoData: type bitmap has query type `"
                                ++ show qtype
                                ++ "`."
                    | otherwise = Right $ nsecR_WildcardNoData c w
            notElemBitmap <$> wild qnames

        qnames = getProps qname

        getProps name =
            [ r
            | refine <- refines
            , Just r <- [refine name]
            ]

        match xs = just1 [x | M x <- xs]
        cover xs = just1 [x | C x <- xs]
        wild xs = just1 [x | W x <- xs]
        just1 xs = case xs of
            [] -> Nothing
            [x] -> Just x
            _ -> Nothing

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

nsecCovers :: Ord a => a -> a -> a -> Bool
nsecCovers lower upper qv = lower < qv && qv < upper

nsecCoversI :: Ord a => a -> a -> a -> Bool
nsecCoversI lower upper qv = qv < upper || lower < qv

{- In the last NSEC RR, the next-domain is the zone apex,
   so lower bound and upper boundaries are inverted.
   The zone apex is the first NSEC RR in the canonical ordering of the zone.

   https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.1
   "The value of the Next Domain Name field in the last NSEC record in the zone is the name of
    the zone apex (the owner name of the zone's SOA RR). This indicates that the owner name of
    the NSEC RR is the last name in the canonical ordering of the zone." -}

nsecRangeRefines
    :: [NSEC_Range] -> Either String [Domain -> Maybe (RangeProp_ NSEC_Witness)]
nsecRangeRefines ranges
    | length (filter fst results) > 1 =
        Left "NSEC.nsecRangeRefines: multiple inverted records found."
    | otherwise = Right $ concatMap snd results
  where
    results =
        [ (inverted, [withRange, withWild])
        | range@(owner, RD_NSEC{..}) <- ranges
        , let next = nsecNextDomain
              inverted = owner > next
              refineWithRange cover qname
                | qname == owner = Just $ M $ Matches (range, qname)
                | cover owner next qname = Just $ C $ Covers (range, qname)
                | otherwise = Nothing
              withRange
                | inverted = refineWithRange nsecCoversI
                | otherwise = refineWithRange nsecCovers
              withWild qname = unconsLables owner Nothing wildmatch
                where
                  wildmatch w wildsuper
                      | w == fromString "*" && qname `isSubDomainOf` wildsuper = Just $ W $ Wilds (range, qname)
                      | otherwise = Nothing
        ]

unconsLables :: Domain -> a -> (ShortByteString -> Domain -> a) -> a
unconsLables = unconsLabels_

unconsLabels_ :: IsRepresentation a b => a -> c -> (b -> a -> c) -> c
unconsLabels_ rep nothing just = case toWireLabels rep of
    []   ->  nothing
    x:xs ->  just x $ fromWireLabels xs
