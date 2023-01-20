module DNS.Do53.Client (
  -- * Lookups returning each type
    lookupA
  , lookupAAAA
  , lookupMX
  , lookupAviaMX
  , lookupAAAAviaMX
  , lookupNS
  , lookupNSAuth
  , lookupTXT
  , lookupSOA
  , lookupPTR
  , lookupRDNS
  , lookupSRV
  -- * Lookups returning requested RData
  , lookup
  , lookupAuth
  , lookup'
  , lookupAuth'
  -- * Lookups returning DNS Messages
  , lookupRaw
  -- * Lookup configuration for sub resolvers
  , LookupConf
  , defaultLookupConf
  , withLookupConf
  , LookupEnv
  -- ** Accessors
  , lconfSeeds
  , lconfRetry
  , lconfConcurrent
  , lconfCacheConf
  , lconfQueryControls
  , lconfActions
  -- ** Specifying full resolvers
  , Seeds(..)
  -- ** Configuring cache
  , CacheConf
  , defaultCacheConf
  , maximumTTL
  , pruningDelay
  -- ** Actions
  , ResolvActions
  , defaultResolvActions
  , ractionTimeout
  , ractionGenId
  , ractionGetTime
  -- ** Query control
  , QueryControls
  , FlagOp(..)
  , rdFlag
  , adFlag
  , cdFlag
  , doFlag
  , ednsEnabled
  , ednsSetVersion
  , ednsSetUdpSize
  , ednsSetOptions
  , ODataOp(..)
  ) where

import Prelude hiding (lookup)

import DNS.Do53.Lookup
import DNS.Do53.LookupX
import DNS.Do53.Query
import DNS.Do53.Types
