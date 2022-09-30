# Extensible DNS libraries written purely in Haskell

This is a new series of DNS libraries based on the experience of the [dns](https://github.com/kazu-yamamoto/dns) library in Haskell. The dns library has two flaws:

- Resource records are not extensible
- Resource records are not friendly to caching

Resource records are implemented as a sum type. The third party library cannot extend them. The only way to extend them is to send a pull request to the dns library.

Some resource records use `ByteString` internally. So, if they are cached for a long time, fragmentation happens.

This new library uses typeclasses to extend resource records and uses `ShortByteString` in them.
