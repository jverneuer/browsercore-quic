# @browsercore/quic


[![npm version](https://img.shields.io/npm/v/@browsercore/quic)](https://www.npmjs.com/package/@browsercore/quic)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-quic/main/.github/coverage-badge.json)](https://github.com/jverneuer/browsercore-quic/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-quic/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-quic/actions/workflows/ci.yml)

QUIC transport (RFC 9000) — packet headers, frames, packet protection, streams,
and connection lifecycle over a datagram (UDP) transport.

## Responsibility

Packet header parse/serialization (long + short headers), the full QUIC frame
set (RFC 9000 §12), variable-length integer encoding (RFC 9000 §16), per-stream
state machines, receive reassembly, and flow control (connection + stream
level). The package knows nothing about HTTP/3, TLS, or sockets — it composes
exclusively over an injected `DatagramTransport` and `@browsercore/crypto`.

## What it does NOT know about

- HTTP/3, QPACK, or any application protocol
- TLS 1.3 / the QUIC handshake (key derivation lives in `@browsercore/crypto`)
- UDP, DNS, or sockets
- Browser fingerprints

Higher layers compose exclusively through the `QuicConnection` interface. A
future `@browsercore/http3` opens bidirectional + unidirectional QUIC streams
and never touches QUIC internals. The production UDP transport **never** calls
`node:dgram` directly — it implements `DatagramTransport`, so the backend is
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

## Architecture

```
DatagramTransport (injected UDP)
        │
        ▼
┌─────────────────────────────────────────────┐
│ connection.ts — read loop, packet I/O       │
│   packet.ts   — header parse/serialize       │
│   frame.ts    — frame parse/serialize        │
│   varint.ts   — QUIC varint (RFC 9000 §16)   │
└──────────────┬──────────────────────────────┘
               │ dispatch
               ▼
┌─────────────────────────────────────────────┐
│ stream.ts — stream state machine,           │
│             reassembly, flow control         │
└─────────────────────────────────────────────┘
```

Frames flow up from the transport into the stream manager; the manager emits
control frames (MAX_DATA, MAX_STREAM_DATA, CONNECTION_CLOSE, …) back down to
the connection's packetizer. The connection owns the read loop and packs
outbound frames into short-header (1-RTT) packets.

## Known limitations

- The TLS 1.3 handshake and packet protection (header protection + AEAD
  payload encryption) are out of scope. `connectQuic()` returns a connection
  that moves *unprotected* frames over the transport — the data plane is fully
  functional and unit-tested, but it is not wire-ready without a protection +
  handshake layer on top.
- No congestion controller, no connection migration, no PATH_CHALLENGE /
  PATH_RESPONSE beyond frame relay, and no liveness PING.
