module DNS.IO.Internal (
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

import DNS.IO.Query
import DNS.IO.IO
