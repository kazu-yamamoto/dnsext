module DNS.Do53.Internal (
    -- * IO types
    Recv,
    RecvN,
    RecvMany,
    RecvManyN,
    Send,
    SendMany,

    -- * TCP related
    openTCP,
    sendTCP,
    recvTCP,

    -- * Virtual circuit
    sendVC,
    recvVC,
    encodeVCLength,
    decodeVCLength,

    -- * Making recvMany
    recvManyN,
    recvManyNN,

    -- * Resolve
    resolve,
    ResolveEnv (..),

    -- * Resolver information
    ResolveInfo (..),
    defaultResolveInfo,
    ResolveActions (..),
    defaultResolveActions,

    -- * Resolver: DNS over X
    Result (..),
    toResult,
    Reply (..),
    OneshotResolver,
    udpTcpResolver,
    udpResolver,
    tcpResolver,

    -- * Resolver for virtual circuit
    vcResolver,

    -- * Query
    encodeQuery,

    -- * Generating identifier
    singleGenId,
    newConcurrentGenId,

    -- * Misc
    checkRespM,
    UDPRetry,
    VCLimit (..),
    LookupEnv (..),
    modifyLookupEnv,
    withLookupConfAndResolver,
    withTCPResolver,
    lazyTag,
)
where

import DNS.Do53.Do53
import DNS.Do53.IO
import DNS.Do53.Id
import DNS.Do53.Lookup
import DNS.Do53.Query
import DNS.Do53.Resolve
import DNS.Do53.Types
import DNS.Do53.VC
