module DNS.Do53.Internal (
    -- * Receiving DNS messages
    receive
  , receiveFrom
  , receiveVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , send
  , sendTo
  , sendVC
  , encodeVCLength
  ) where

import DNS.Do53.IO
