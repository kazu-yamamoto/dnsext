module DNS.Do53.Internal (
    openTCP
    -- * Receiving DNS messages
  , recvTCP
  , recvVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , sendTCP
  , sendVC
  , encodeVCLength
  ) where

import DNS.Do53.IO
