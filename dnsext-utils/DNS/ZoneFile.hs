module DNS.ZoneFile (
    LexParser,
    ZoneParser,
    runLexParser,
    runZoneParser,
    module DNS.ZoneFile.Types,
    module DNS.ZoneFile.Lexer,
    module DNS.ZoneFile.Parser,
    module DNS.ZoneFile.IO,
    ) where

-- ghc packages
import qualified Data.ByteString.Lazy as LB

-- this package
import DNS.ZoneFile.Types
import DNS.ZoneFile.Lexer hiding (Parser)
import qualified DNS.ZoneFile.Lexer as L
import DNS.ZoneFile.Parser hiding (Parser, runParser, parseLineRR, parseFile)
import qualified DNS.ZoneFile.Parser as P
import DNS.ZoneFile.IO

type LexParser a = L.Parser a

runLexParser :: LexParser a -> LB.ByteString -> Either String (a, LB.ByteString)
runLexParser = runParser

type ZoneParser a = P.Parser a

runZoneParser :: ZoneParser a -> Context -> [Token] -> Either String ((a, Context), [Token])
runZoneParser = P.runParser
