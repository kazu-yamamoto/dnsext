module DNS.Do53.Server (
    -- * Receiving DNS messages
    receive
  , receiveFrom
  , receiveVC
    -- * Sending pre-encoded messages
  , send
  , sendTo
  , sendVC
  , sendAll
  ) where

import DNS.Do53.IO
