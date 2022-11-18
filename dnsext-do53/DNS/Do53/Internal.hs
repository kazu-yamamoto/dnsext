module DNS.Do53.Internal (
    -- * Receiving DNS messages
    receive
  , receiveVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , send
  , sendVC
  , encodeVCLength
  ) where

import DNS.Do53.IO
