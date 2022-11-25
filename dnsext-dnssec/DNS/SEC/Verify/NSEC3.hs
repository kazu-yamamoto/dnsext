{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSEC3 where

import Data.String (fromString)
import Data.ByteString.Short (fromShort)

-- base32
import qualified Data.ByteString.Base32.Hex as B32Hex

-- dnsext-types
import DNS.Types hiding (qname)
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.SEC.Imports
import DNS.SEC.Types
import DNS.SEC.Flags ( NSEC3_Flag (OptOut) )
import DNS.SEC.Verify.Types


{- find NSEC3 records which covers or matches with qname or super names of qname,
   to recognize non-existence of domain or non-existence of RRset -}
verify :: [(NSEC3_Range, Domain -> Opaque)] -> Domain -> TYPE -> Either String NSEC3_Result
verify n3s domain qtype = n3RangeRefines n3s >>= findEncloser
  where
    findEncloser refines =
      maybe (Left "NSEC3.verify: no NSEC3 encloser") id $
      getNoData props
      <|>
      {- find non-existence of RRset -}
      loop stepNE ppairs
      <|>
      {- find wildcard-expansion result -}
      loop stepWE props
      where
        {- reuse computed range-props for closest-name and next-closer-name -}
        ppairs = zip props (tail props)
        props = map rangePropSet $ superDomains domain ++ [fromString "."]

        {- return first result or continue -}
        loop :: (a -> Maybe b)
             -> [a] -> Maybe b
        loop step = foldr stepK Nothing
          where
            -- stepK :: a -> Maybe b -> Maybe b
            stepK p k = step p <|> k

        getNoData :: [[RangeProp]] -> Maybe (Either String NSEC3_Result)
        getNoData []           =  Nothing
        getNoData (exists:_)   =  notElemBitmap <$> just1 (matches exists)
          where
            notElemBitmap m@( Matches ((_, RD_NSEC3 {..}), _) )
              | qtype `elem` nsec3_types  =  Left $ "NSEC3.verify: NoData: type bitmap has query type `" ++ show qtype ++ "`."
              | otherwise                 =  Right $ n3r_noData m

        {- next-closer-name 'cover' for qname and closest-name 'match' for super-name are checked at the same time -}
        stepNE :: ([RangeProp], [RangeProp]) -> Maybe (Either String NSEC3_Result)
        stepNE (nexts, closests) = do
          nextCloser@(Covers ((_, nextN3), _))  <- just1 $ covers nexts
          closest@(Matches (_, cn))             <- just1 $ matches closests

          let wildcardProps = rangePropSet (fromString "*" <> cn)
              takeWildcardCover    = just1 $ covers wildcardProps
              takeWildcardMatches  = just1 $ matches wildcardProps
              takeWildcardNoData   = notElemBitmap <$> takeWildcardMatches
                where
                  notElemBitmap m@( Matches ((_, RD_NSEC3 {..}), _) )
                    | qtype `elem` nsec3_types  =  Left $ "NSEC3.verify: WildcardNoData: type bitmap has query type `" ++ show qtype ++ "`."
                    | otherwise                 =  Right $ n3r_wildcardNoData closest nextCloser m
              optOutDelegation
                | OptOut `elem` nsec3_flags nextN3  =  Right $ n3r_optOutDelegation closest nextCloser
                | otherwise                         =  Left $ "NSEC3.verify: wildcard name is not matched or covered."
          ( Right . n3r_nameError closest nextCloser <$> takeWildcardCover  <|>
            takeWildcardNoData                                              <|>
            pure optOutDelegation )

        stepWE :: [RangeProp] -> Maybe (Either String NSEC3_Result)
        stepWE nexts = Right . n3r_wildcardExpansion <$> just1 (covers nexts)

        rangePropSet :: Domain -> [RangeProp]
        rangePropSet qname =
          [ r
          | refine <- refines
          , Just r <- [refine qname]
          ]

        matches xs = [ x | M x <- xs ]
        covers  xs = [ x | C x <- xs ]
        just1 xs = case xs of
          []   ->  Nothing
          [x]  ->  Just x
          _    ->  Nothing

newtype Matches a = Matches a  deriving Show
newtype Covers a  = Covers a   deriving Show

n3r_nameError :: Matches NSEC3_Witness -> Covers NSEC3_Witness -> Covers NSEC3_Witness -> NSEC3_Result
n3r_nameError (Matches closest) (Covers next) (Covers wildcard) =
  N3Result_NameError closest next wildcard

n3r_noData :: Matches NSEC3_Witness -> NSEC3_Result
n3r_noData (Matches closest) =
  N3Result_NoData closest

n3r_optOutDelegation :: Matches NSEC3_Witness -> Covers NSEC3_Witness -> NSEC3_Result
n3r_optOutDelegation (Matches closest) (Covers next) =
  N3Result_OptOutDelegation closest next

n3r_wildcardExpansion :: Covers NSEC3_Witness -> NSEC3_Result
n3r_wildcardExpansion (Covers next) =
  N3Result_WildcardExpansion next

n3r_wildcardNoData :: Matches NSEC3_Witness -> Covers NSEC3_Witness -> Matches NSEC3_Witness -> NSEC3_Result
n3r_wildcardNoData (Matches closest) (Covers next) (Matches wildcard) =
  N3Result_WildcardNoData closest next wildcard

type RangeProp = RangeProp_ NSEC3_Witness

---

data RangeProp_ a
  = M (Matches a)
  | C (Covers  a)
  deriving Show

n3Covers :: Ord a => a -> a -> a -> Bool
n3Covers lower upper qv = lower < qv && qv < upper

n3CoversR :: Ord a => a -> a -> a -> Bool
n3CoversR lower upper qv = qv < upper || lower < qv
  {- https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7
     "The value of the Next Hashed Owner Name
      field in the last NSEC3 RR in the zone is the same as the hashed
      owner name of the first NSEC3 RR in the zone in hash order." -}

{- get funcs to compute 'match' or 'cover' with ranges from NSEC3 record-set -}
n3RangeRefines :: [(NSEC3_Range, Domain -> Opaque)] -> Either String [(Domain -> Maybe (RangeProp_ NSEC3_Witness))]
n3RangeRefines ranges0 = do
  (((owner1,_),_), _)  <- maybe (Left "NSEC3.n3RangeRefines: no NSEC3 records") Right $ uncons ranges0
  (_, zname)           <- maybe (Left "NSEC3.n3RangeRefines: no zone name")     Right $ unconsName owner1

  let rs = [ (ownerBytes, r)
           | r@((rrn, RD_NSEC3 {..}), _) <- ranges0
           , nsec3_flags `elem` [ [], [OptOut] ]
           {- https://datatracker.ietf.org/doc/html/rfc5155#section-8.2
              "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one." -}
           , Just (owner32h, parent) <- [ unconsName rrn ]
           , parent == zname
           , ownerBytes <- decodeBase32 owner32h
           ]
  takeRefines rs

  where
    unconsName :: Domain -> Maybe (ShortByteString, Domain)
    unconsName name = case toWireLabels name of
      x:xs ->  Just (x, fromWireLabels xs)
      []   ->  Nothing

    decodeBase32 :: ShortByteString -> [Opaque]
    decodeBase32 part = either (const []) ((: []) . Opaque.fromByteString) $ B32Hex.decodeBase32 $ fromShort part

    takeRefines :: [(Opaque, (NSEC3_Range, Domain -> Opaque))] -> Either String [(Domain -> Maybe (RangeProp_ NSEC3_Witness))]
    takeRefines ranges
      | length (filter fst results) > 1  =  Left "NSEC3.n3RangeRefines: multiple rounded records found."
      | otherwise                        =  Right $ map snd results
      where
        results =
          [ (rounded, result)
          | (owner, (rangeB32H@(_, RD_NSEC3 {..}), hash)) <- ranges
          , let next = nsec3_next_hashed_owner_name  {- binary hashed value, not base32hex -}
                rounded = owner > next
                refineWithRange cover qname
                  {- owner and next are decoded range, not base32hex -}
                  | hq == owner          =  Just $ M $ Matches (rangeB32H, qname)
                  | cover owner next hq  =  Just $ C $ Covers  (rangeB32H, qname)
                  | otherwise            =  Nothing
                  where hq = hash qname
                result
                  | rounded    =  refineWithRange n3CoversR
                  | otherwise  =  refineWithRange n3Covers
                  {- base32hex does not change hash ordering. https://datatracker.ietf.org/doc/html/rfc5155#section-1.3
                     "Terminology: Hash order:
                      Note that this order is the same as the canonical DNS name order specified in [RFC4034],
                      when the hashed owner names are in base32, encoded with an Extended Hex Alphabet [RFC4648]." -}
          ]
