module DNS.Wire.Types where

import Data.Array (Array)
import Data.ByteString.Short

type Label = ShortByteString
type Labels = [Label]
type WireLabels = Array Int Label

type Position = Int
