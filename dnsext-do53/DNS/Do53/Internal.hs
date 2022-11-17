module DNS.Do53.Internal (
    encodeQuery
    -- * Receiving DNS messages
  , receive
  , receiveFrom
  , receiveVC
    -- * Sending pre-encoded messages
  , send
  , sendTo
  , sendVC
  , sendAll
  ) where

import DNS.Do53.Query
import DNS.Do53.IO
