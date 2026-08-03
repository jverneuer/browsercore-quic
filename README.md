# @browsercore/quic

[![npm version](https://img.shields.io/npm/v/@browsercore/quic)](https://www.npmjs.com/package/@browsercore/quic)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-quic/main/coverage/badge.json)](https://github.com/jverneuer/browsercore-quic/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-quic/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-quic/actions/workflows/ci.yml)

QUIC transport (RFC 9000) — packet headers, frames, streams, and connection
lifecycle over a datagram (UDP) transport. No knowledge of HTTP/3 or TLS
handshake semantics; composes exclusively over an injected
`DatagramTransport` and `@browsercore/crypto`.

## Responsibility

Packet header parse/serialization (long + short headers, RFC 9000 §17), the
full QUIC frame set (RFC 9000 §12), variable-length integer encoding
(RFC 9000 §16), truncated packet-number coding (RFC 9000 §17.1), per-stream
state machines with receive reassembly, and flow control (connection +
stream level, RFC 9000 §4). The TLS 1.3 handshake and packet protection
are intentionally out of scope (see [Known limitations](#known-limitations)).

## What it does NOT know about

- HTTP/3, QPACK, or any application protocol
- TLS 1.3 / the QUIC handshake (key derivation lives in `@browsercore/crypto`)
- UDP, DNS, or sockets
- Browser fingerprints

Higher layers compose exclusively through the `QuicConnection` interface. A
future `@browsercore/http3` opens bidirectional + unidirectional QUIC streams
and never touches QUIC internals. The production UDP transport **never**
calls `node:dgram` directly — it implements `DatagramTransport`, so the
backend is replaceable (a test double, a `node:dgram` adapter, a mock).

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
| `serializeFrame` / `readFrames` / `decodeFrame` | functions | Frame serialization + incremental parsing |
| `encodeVarint` / `decodeVarint` / `encodeVarintInto` / `readVarint` / `getVarintEncodedLength` / `prefixMask` | functions | QUIC varint encoding (RFC 9000 §16) |
| `parsePacketHeader` / `serializeShortHeader` / `serializeLongHeader` | functions | Packet header parse/serialize (RFC 9000 §17) |
| `decodePacketNumber` / `encodePacketNumber` / `readPacketNumber` | functions | Truncated packet-number coding (RFC 9000 §17.1) |

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

## Implementation state

Audited against `src/`. The data plane is complete and unit-tested over a fake
datagram transport; several production concerns are intentionally TODO.

### Done

- **`frame/varint.ts`** — QUIC varint (RFC 9000 §16): `encodeVarint`,
  `decodeVarint`, `encodeVarintInto`, `readVarint` (pull-based),
  `getVarintEncodedLength`, `prefixMask`. All four 1/2/4/8-byte forms,
  shortest-length encoding, range-checked.
- **`packet/packet.ts`** — packet headers (RFC 9000 §17): `parsePacketHeader`
  (long + short forms), `serializeLongHeader`, `serializeShortHeader`,
  `decodePacketNumber` / `encodePacketNumber` / `readPacketNumber` for
  truncated packet-number coding (RFC 9000 §17.1).
- **`frame/frame.ts`** — the full QUIC frame set (RFC 9000 §12):
  `serializeFrame` + `decodeFrame` + `readFrames` (incremental, pull-based)
  for every `QuicFrame` variant — PADDING, PING, ACK/ACK_ECN, RESET_STREAM,
  STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM (0x08–0x0f with off/len/fin flags
  folded into the type byte), MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
  DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID,
  RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE,
  CONNECTION_CLOSE_APP, HANDSHAKE_DONE. Exhaustive switches with
  `assertNever`.
- **`stream/stream.ts`** — stream state machine + flow control
  (RFC 9000 §2, §4): `createStreamManager` with per-stream send queues,
  receive reassembly by offset, FIN delivery, connection-level and per-stream
  flow control with MAX_DATA/MAX_STREAM_DATA replenishment and DATA_BLOCKED /
  STREAM_DATA_BLOCKED signaling. RESET_STREAM and STOP_SENDING drive the
  `QuicStream` to reject waiters with typed errors.
- **`connection.ts`** — connection lifecycle + datagram read loop
  (RFC 9000 §5, §12): `connectQuic()` and `QuicConnectionImpl`. Frame
  dispatch routes data-plane frames to the stream manager and flushes the
  outbound frame buffer into short-header packets (split at the 1200-byte
  UDP payload limit). Connection teardown and fatal errors flow through
  `teardown` / `handleFatal`.
- **`errors.ts`** — a `kind`-discriminated error hierarchy (one class per
  failure mode, each with `cause`); see the [Types](#types) table.
- **`types.ts`** — branded `StreamId` / `ConnectionId`, the exhaustive
  `QuicFrame` discriminated union, `QuicConnection` / `QuicStream` /
  `DatagramTransport` interfaces, and QUIC varint / frame-type /
  transport-parameter constants.

### Not yet implemented (TODO)

- **Packet protection** — header protection + AEAD payload encryption
  (RFC 9000 §5). `connectQuic()` returns a connection that moves *unprotected*
  frames over the transport. The data plane is fully functional and tested
  this way, but it is not wire-ready without a protection layer.
- **TLS 1.3 handshake** — the QUIC handshake (RFC 9000 §19) over CRYPTO
  frames, driving the TLS state machine to derive the QUIC key schedule.
- **Transport-parameter wire encoding/parsing** — the `TransportParameter`
  id constants exist, and local defaults are resolved, but transport
  parameters are not yet serialized onto long headers or parsed from the peer;
  received peer parameters fall back to hardcoded defaults.
- **Version negotiation** — `applyHeader` accepts long headers but ignores the
  version field; no VERSION_NEGOTIATION handling.
- **Congestion controller** — none.
- **Connection migration** — no NAT rebinding; PATH_CHALLENGE / PATH_RESPONSE
  are parsed/serialized but only relayed, never initiated or validated.
- **Liveness PING** — PING frames are recognized but not paced; ACK frames are
  not paced either.

## Known limitations

- The TLS 1.3 handshake and packet protection (header protection + AEAD
  payload encryption) are out of scope. `connectQuic()` returns a connection
  that moves *unprotected* frames over the transport — the data plane is fully
  functional and unit-tested, but it is not wire-ready without a protection +
  handshake layer on top.
- No congestion controller, no connection migration, no PATH_CHALLENGE /
  PATH_RESPONSE beyond frame relay, and no liveness PING.
- Transport parameters are not yet negotiated on the wire; peer values fall
  back to defaults.

## Development

`@browsercore/quic` is an ESM-only package (Node >= 26) and shares its build /
test / lint configuration through the `@browsercore/dev` package, which supplies
the base `tsconfig.base.json`, the `oxlint` base config, and the
`definePackageConfig` helper used by `vitest.config.ts`:

```ts
// vitest.config.ts
import { definePackageConfig } from "@browsercore/dev/vitest";
export default definePackageConfig({ name: "quic" });
```

`@browsercore/dev` is declared as a file dependency
(`"@browsercore/dev": "file:../dev"`) and lives alongside this repo in the
parent directory. Any change to the shared config applies to this package on
the next install / typecheck.

The protocol code never imports `node:*` directly — it composes over the
injected `DatagramTransport` interface — so the data plane is unit-tested
against a fake datagram transport (`tests/fake-transport.ts`) with no real
network I/O.

```sh
npm install          # install dependencies (incl. file:../dev)
npm run typecheck    # tsc --noEmit
npm run lint         # oxlint --type-aware src/
npm run test         # vitest run
npm run test:watch   # vitest (interactive watch mode)
npm run build        # tsc -p tsconfig.build.json (emit to dist/)
```

Run a **single test** with vitest's file filter:

```sh
npx vitest run tests/connection.test.ts
```

Run tests by **name pattern**:

```sh
npx vitest run -t "open a bidirectional stream"
```

Produce a coverage report:

```sh
npx vitest run --coverage
```

CI runs in the order **typecheck → lint → test → build**. If the version in
`package.json` changes on `main`, it auto-publishes to npm with provenance and
creates a git tag + GitHub Release.
