{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module DNS.Parser.State where

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State
import Control.Monad.Trans.Except (Except, runExcept, throwE)
import Data.Maybe (fromMaybe)
import Data.Monoid (Last (..))

import DNS.Parser.Class

type Error = Last String
type Parser s = StateT s (StateT (Int, Int) (Except Error))

runError :: Error -> String
runError = fromMaybe "<empty error>" . getLast

runParser :: Parser s a -> s -> Either String (a, s)
runParser p in_ = either (Left . runError) Right $ runExcept (evalStateT (runStateT p in_) (1, 0))

instance CaseCons t s => MonadParser t s (Parser s) where
    getInput = get
    putInput = put
    raiseParser = lift . lift . throwE . Last . Just
    getPos = lift get
    putPos = lift . put
