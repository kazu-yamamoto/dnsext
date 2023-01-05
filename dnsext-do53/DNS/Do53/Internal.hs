module DNS.Do53.Internal (
    -- * Receiving DNS messages
    recvTCP
  , recvVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , sendUDP
  , sendTCP
  , sendVC
  , encodeVCLength
  ) where

import DNS.Do53.IO
