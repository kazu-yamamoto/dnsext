module DNS.Wire.Types where

import Data.ByteString.Short
import Data.Vector (Vector)

type Label = ShortByteString
type Labels = [Label]
type WireLabels = Vector Label

type Position = Int
