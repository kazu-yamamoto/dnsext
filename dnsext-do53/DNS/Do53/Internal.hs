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

    -- * Resolver
    Resolver,
    Result (..),
    toResult,
    Reply (..),

    -- * Pipeline resolver
    PipelineResolver,
    withTCPResolver,
    withVCResolver,

    -- * One-shot resolver
    OneshotResolver,
    udpTcpResolver,
    udpResolver,
    tcpResolver,
    vcResolver,

    -- * Resolver information
    ResolveInfo (..),
    defaultResolveInfo,
    UDPRetry,
    VCLimit (..),
    ResolveActions (..),
    defaultResolveActions,

    -- * One shot resolve function
    resolve,
    ResolveEnv (..),

    -- * Query
    encodeQuery,

    -- * Generating identifier
    singleGenId,
    newConcurrentGenId,

    -- * Misc
    LookupEnv (..),
    checkRespM,
    withLookupConfAndResolver,
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
