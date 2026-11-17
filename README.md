# @browsercore/quic


[![npm version](https://img.shields.io/npm/v/@browsercore/quic)](https://www.npmjs.com/package/@browsercore/quic)
[![coverage](https://img.shields.io/endpoint?url=https://jverneuer.github.io/browsercore-quic/badge.json)](https://jverneuer.github.io/browsercore-quic/COVERAGE.md)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-quic/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-quic/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@browsercore/quic.svg)](LICENSE)

QUIC transport (RFC 9000): packet headers, frames, packet protection, streams,
and connection lifecycle over a datagram (UDP) transport.

## Responsibility

Packet header parse/serialization (long + short headers), the full QUIC frame
set (RFC 9000 §12), variable-length integer encoding (RFC 9000 §16), per-stream
state machines, receive reassembly, and flow control (connection + stream
level). The package knows nothing about HTTP/3, TLS, or sockets. It composes
exclusively over an injected `DatagramTransport` and `@browsercore/crypto`.

## What it does NOT know about

- HTTP/3, QPACK, or any application protocol
- TLS 1.3 handshake internals: the handshake runs through an injected
  `TlsHandshakeEngine` (see below); quic never imports a protocol package
  directly (key derivation lives in `@browsercore/crypto`)
- UDP, DNS, or sockets
- Browser fingerprints

Higher layers compose exclusively through the `QuicConnection` interface. A
future `@browsercore/http3` opens bidirectional + unidirectional QUIC streams
and never touches QUIC internals. The production UDP transport **never** calls
`node:dgram` directly. It implements `DatagramTransport`, so the backend is
replaceable (a test double, a `node:dgram` adapter, a mock).

## Public API

```ts
import { connectQuic, ConnectionClosedError } from "@browsercore/quic";

const conn = await connectQuic({
    transport, // an injected DatagramTransport (UDP)
    peer: { address: "93.184.216.34", port: 443, family: 6 },
    serverName: "example.com",
    initialDcid: new Uint8Array([1, 2, 3, 4]),
    initialScid: new Uint8Array([5, 6, 7, 8]),
});

// Open a bidirectional stream (request/response in HTTP/3).
const stream = await conn.openBidirectionalStream();
await stream.write(new TextEncoder().encode("hello"));
await stream.close();
const chunk = await stream.read();

// Accept a peer-opened unidirectional stream (control / QPACK / push).
const control = await conn.acceptUnidirectionalStream();

await conn.close(0x00n, "graceful shutdown");
```

## Types

| Export | Kind | Purpose |
| --- | --- | --- |
| `connectQuic` | function | Establish a QUIC connection over a datagram transport |
| `QuicConnectionImpl` | class | Concrete connection; implements `QuicConnection` |
| `QuicConnection` | interface | Public contract HTTP/3 depends on |
| `QuicStream` | interface | A reliable, ordered byte stream |
| `QuicOptions` | interface | Options for `connectQuic` |
| `DatagramTransport` | interface | Injected UDP abstraction |
| `QuicFrame` | type | Every QUIC frame variant (exhaustive union) |
| `QuicFrameType` | const | Frame type identifiers |
| `StreamId` | type | Branded 62-bit stream id |
| `ConnectionId` | type | QUIC connection id (0–255 bytes) |
| `LongPacketType` | const | Long-header packet types (Initial/Handshake/0-RTT/Retry) |
| `TransportParameter` | const | Transport-parameter identifiers |
| `QuicTransportParameters` | interface | Locally-advertised transport parameters |
| `QuicError` | class | Base class for all QUIC errors |
| `ConnectionClosedError` | class | Peer closed the connection |
| `ResetStreamError` | class | Peer reset a stream |
| `StopSendingError` | class | Peer asked us to stop sending |
| `FlowControlError` | class | Flow-control window violated |
| `PacketParseError` | class | Malformed packet |
| `FrameParseError` | class | Malformed frame |
| `TransportParameterError` | class | Peer violated transport parameters |
| `HandshakeTimeoutError` | class | Handshake did not complete in time |
| `createStreamManager` | function | Create the stream state machine + flow control |
| `serializeFrame` / `readFrames` | functions | Frame serialization + incremental parsing |
| `encodeVarint` / `decodeVarint` | functions | QUIC varint encoding |
| `parsePacketHeader` / `serializeShortHeader` / `serializeLongHeader` | functions | Packet header parse/serialize |
| `decodePacketNumber` / `encodePacketNumber` | functions | Truncated packet-number coding |
| `TlsHandshakeEngine` | interface | Contracts seam for the injected TLS engine (`@browsercore/contracts`) |
| `ClientHelloConfig` | interface | Canonical ClientHello offer shape (`@browsercore/contracts`) |
| `Clock` | interface | Canonical time source (`@browsercore/contracts`) |

## Architecture

```
DatagramTransport (injected UDP)
        │
        ▼
┌─────────────────────────────────────────────┐
│ connection.ts:  read loop, packet I/O       │
│   packet.ts  :  header parse/serialize       │
│   frame.ts   :  frame parse/serialize        │
│   varint.ts  :  QUIC varint (RFC 9000 §16)   │
└──────────────┬──────────────────────────────┘
               │ dispatch
               ▼
┌─────────────────────────────────────────────┐
│ stream.ts:  stream state machine,           │
│             reassembly, flow control         │
└─────────────────────────────────────────────┘
```

Frames flow up from the transport into the stream manager; the manager emits
control frames (MAX_DATA, MAX_STREAM_DATA, CONNECTION_CLOSE, …) back down to
the connection's packetizer. The connection owns the read loop and packs
outbound frames into short-header (1-RTT) packets.

## Platform threading

`QuicOptions` accepts an optional `platform?: Platform` field. When supplied,
any service not passed as an individual field is resolved from the Platform
composition root:

| Option field | Resolved from |
| --- | --- |
| `crypto` | `platform.crypto.provider` |
| `events` | `platform.events` |
| `clock` | `platform.time` (a `Clock` itself; `Time` ≡ `Clock` since contracts 0.2.6) |

Individual fields always take precedence, so existing callers that pass
`crypto`/`events`/`clock` directly keep working unchanged. This is the migration path
toward DI through Platform: callers move from passing individual service fields
to threading a single Platform (assembled by `browsersmith`) through every
protocol package. See `@browsercore/contracts` for the `Platform` interface.

## TLS handshake engine injection

Per the no-hard-wires invariant ("protocol packages must never import each
other directly; all inter-package communication flows through Platform
interfaces in `@browsercore/contracts`"), quic drives the TLS 1.3 handshake
(RFC 9001 §4) through the contracts `TlsHandshakeEngine` interface,
`runHandshake` / `generateKeyShares` / `cipherSuiteToAead`, never through a
direct dependency on `@browsercore/tls`. Every type crossing the seam
(`TlsHandshakeContext`, `ClientHelloConfig`, `ServerHello`, `TrafficSecrets`,
`CipherSuite`, …) comes from `@browsercore/contracts` as well.

**Composition-root wiring** (the pattern every `browsersmith` 0.0.19+ caller
uses): the root imports the concrete engine once and injects it, and quic only
ever sees the interface.

```ts
import { connectQuic } from "@browsercore/quic";
import { runHandshake, generateKeyShares, cipherSuiteToAead } from "@browsercore/tls";

const conn = await connectQuic({
    // …transport, peer, ids, crypto, events as usual…
    handshakeEngine: { runHandshake, generateKeyShares, cipherSuiteToAead },
});
```

**Deprecation note: the dynamic default.** When `handshakeEngine` is omitted,
the handshake falls back to ONE dynamic `import("@browsercore/tls")` wrapping
the package's three exported functions into the engine object
(`loadDefaultHandshakeEngine` in `src/handshake/quic-handshake.ts`). That
loader is the package's only remaining touchpoint on `@browsercore/tls` and
exists purely so 0.2.x callers keep working; composition roots should inject
explicitly. Engine internals are never reached.

**Canonical Clock.** `QuicOptions.clock` and `platform.time` are the canonical
`Clock` from `@browsercore/contracts` (`now` / `monotonic` / `sleep` /
`setTimeout` / `clearTimeout`). The handshake's certificate-validity time is
read from the resolved clock (`Math.floor(clock.now() / 1000)`), never from
`Date.now()` directly, so cert-time behavior is deterministic under an
injected fake clock.

**Testing with a fake engine.** The sanctioned swap pattern (the same
structural-implementation approach as http3's `fake-quic` compatibility test)
is a local fake `TlsHandshakeEngine` that mutates the handshake context the
way a completed handshake would. See
`tests/handshake-engine-injection.test.ts`, which drives a full `connectQuic`
handshake with the engine injected and asserts the deprecated dynamic
`@browsercore/tls` fallback import is never taken.

## Known limitations

- 0-RTT, KeyUpdate, key-phase-bit handling, and connection migration beyond
  PATH_CHALLENGE / PATH_RESPONSE are out of scope, as is any congestion
  controller or liveness PING. `skipHandshake: true` returns an *unprotected*
  connection (data plane fully functional, not wire-ready).

## Contributing

Contributions are welcome: bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-quic/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
