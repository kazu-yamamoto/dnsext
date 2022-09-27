module DNS.Types.Internal (
  -- * Classes
    ResourceData(..)
  , OptData(..)
  -- * High level
  , putDNSMessage
  , putHeader
  , putDNSFlags
  , putQuestion
  , putResourceRecord
  , putRData
  -- * Middle level
  , putDomain
  , getDomain
  , putMailbox
  , getMailbox
  , putOpaque
  , getOpaque
  , getLenOpaque
  , putTYPE
  , getTYPE
  -- * Low level
  , module DNS.StateBinary
  ) where

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Message
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Type
