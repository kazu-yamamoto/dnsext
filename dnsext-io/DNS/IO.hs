module DNS.IO (
  -- * Lookups returning requested RData
    lookup
  , lookupAuth
  -- * Lookups returning DNS Messages
  , lookupRaw
  , lookupRawCtl
  , lookupRawCtlRecv
  -- * Type and function for resolver
  , Resolver
  , withResolver
  -- * Intermediate data type for resolver
  , ResolvSeed
  , makeResolvSeed
  -- * Configuration for resolver
  , ResolvConf
  , defaultResolvConf
  -- ** Accessors
  , resolvInfo
  , resolvTimeout
  , resolvRetry
  , resolvConcurrent
  , resolvCache
  , resolvQueryControls
  -- ** Specifying DNS servers
  , FileOrNumericHost(..)
  -- ** Configuring cache
  , CacheConf
  , defaultCacheConf
  , maximumTTL
  , pruningDelay
  -- * Query control
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

import DNS.IO.Lookup
import DNS.IO.Query
import DNS.IO.Resolver

