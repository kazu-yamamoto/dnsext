{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSEC where

import Data.String (fromString)

-- dnsext-types
import DNS.Types hiding (qname)

-- this package
import DNS.SEC.Imports
import DNS.SEC.Types
import DNS.SEC.Verify.Types


verify :: Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_Result
verify zone ranges qname qtype = do
  refines <- nsecRangeRefines ranges
  findEncloser refines
  where
    findEncloser refines =
      maybe (Left "NSEC.verify: no NSEC encloser") id $
      getWildcardNoData
      <|>
      getNameError
      <|>
      getUnsignedDelegation
      <|>
      getNoData
      <|>
      getWildcardExpansion
      where
        getNameError = Right <$> (nsecR_NameError <$> cover qnames <*> cover wildcards)
          where wildcards = getProps (fromString "*" <> zone)

        getNoData = notElemBitmap <$> match qnames
          where
            notElemBitmap m@(Matches ((_, RD_NSEC {..}), _))
              | qtype `elem` nsecTypes  =  Left $ "NSEC.verify: NoData: type bitmap has query type `" ++ show qtype ++ "`."
              | otherwise               =  Right $ nsecR_NoData m

        getUnsignedDelegation = do
          c@( Covers ((owner, RD_NSEC {..}), qn) ) <- cover qnames
          guard $ owner /= zone  {- owner MUST be sub-level, not zone-top -}
          guard $ qn `isSubDomainOf` owner && NS `elem` nsecTypes {- super-domain is NS -}
          guard $ DS `notElem` nsecTypes  {- not signed -}
          return $ Right $ nsecR_UnsignedDelegation c

        getWildcardExpansion = Right . nsecR_WildcardExpansion <$> cover qnames

        getWildcardNoData = do
          c@( Covers ((_, _), qn) ) <- cover qnames
          let wildcards = [ M m | range <- ranges, Just (wsuper, m) <- [wildMatches range], qn `isSubDomainOf` wsuper ]
              notElemBitmap m@( Matches ((_, RD_NSEC {..}), _) )
                | qtype `elem` nsecTypes  =  Left $ "NSEC.verify: WildcardNoData: type bitmap has query type `" ++ show qtype ++ "`."
                | otherwise               =  Right $ nsecR_WildcardNoData c m
          notElemBitmap <$> match wildcards

        qnames = getProps qname
        wildMatches range@(owner, _) =
          case unconsName owner of
            Just (hd, tl) | hd == fromString "*"  ->  Just (tl, rangeMatches range)
            _                                     ->  Nothing

        getProps name =
          [ r
          | refine <- refines
          , Just r <- [refine name]
          ]

        match xs = just1 [ x | M x <- xs ]
        cover xs = just1 [ x | C x <- xs ]
        just1 xs = case xs of
          []   ->  Nothing
          [x]  ->  Just x
          _    ->  Nothing

        unconsName :: Domain -> Maybe (ShortByteString, Domain)
        unconsName name = case toWireLabels name of
          x:xs ->  Just (x, fromWireLabels xs)
          []   ->  Nothing

newtype Matches a = Matches a  deriving Show
newtype Covers a  = Covers a   deriving Show

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

nsecR_WildcardNoData :: Covers NSEC_Witness -> Matches NSEC_Witness -> NSEC_Result
nsecR_WildcardNoData (Covers name) (Matches wildcard) =
  NSECResult_WildcardNoData name wildcard

type RangeProp = RangeProp_ NSEC_Witness

---

data RangeProp_ a
  = M (Matches a)
  | C (Covers  a)
  deriving Show

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

nsecRangeRefines :: [NSEC_Range] -> Either String [Domain -> Maybe (RangeProp_ NSEC_Witness)]
nsecRangeRefines ranges
  | length (filter fst results) > 1  =  Left "NSEC.nsecRangeRefines: multiple inverted records found."
  | otherwise                        =  Right $ map snd results
  where
    results =
      [ (inverted, result)
      | range@(owner, RD_NSEC {..}) <- ranges
      , let next = nsecNextDomain
            inverted = owner > next
            refineWithRange cover qname
              | qname == owner          =  Just $ M $ Matches (range, qname)
              | cover owner next qname  =  Just $ C $ Covers  (range, qname)
              | otherwise               =  Nothing
            result
              | inverted   =  refineWithRange nsecCoversI
              | otherwise  =  refineWithRange nsecCovers
      ]
