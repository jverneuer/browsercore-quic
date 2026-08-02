# @browsercore/quic — Implementation Plan

QUIC transport (RFC 9000) over a datagram (UDP) transport. Implement in this
order; each step is independently testable.

## Step 1 — QUIC varint (DONE)

`encodeVarint()` / `decodeVarint()` / `getVarintEncodedLength()` for the 1/2/4/8-
byte variable-length integer encoding (RFC 9000 §16). Used for stream ids, frame
types, frame lengths, packet numbers, and transport-parameter ids/values.

Tests: encode + decode round-trip for each form; assert the shortest encoding
is selected; reject negative / out-of-range values; decode from an offset.

## Step 2 — Packet header parse/serialize (DONE)

`parsePacketHeader()` / `serializeLongHeader()` / `serializeShortHeader()` for the
long-header (Initial / Handshake / 0-RTT / Retry) and short-header (1-RTT) forms
(RFC 9000 §17). Plus `decodePacketNumber()` / `encodePacketNumber()` for
truncated packet-number coding (RFC 9000 §17.1).

Tests: parse a header back from each serializer; recover a truncated packet
number; read a big-endian packet number.

## Step 3 — Full frame parse/serialize (DONE)

`serializeFrame()` for every `QuicFrame` variant and `readFrames()` /
`decodeFrame()` for incremental parsing from a pull-based byte source (RFC 9000
§12). STREAM frames (0x08–0x0f) fold their off/len/fin flags into the type byte;
the reader/writer handle that transparently.

Tests: round-trip each frame type through `serializeFrame()` + `readFrames()`.

## Step 4 — Stream state machine + flow control (DONE)

`createStreamManager()` and the `StreamState` transitions per RFC 9000 §2, §4.
Each stream reassembles out-of-order STREAM frames by offset into the byte
stream `read()` consumes, and enforces connection-level + per-stream flow
control. The manager emits MAX_DATA / MAX_STREAM_DATA to replenish the peer's
send credit and DATA_BLOCKED / STREAM_DATA_BLOCKED when a window is exhausted.

Tests: open bidirectional / unidirectional streams; deliver in-order and out-of-
order bytes; drop retransmitted overlaps; RESET_STREAM rejects readers;
STOP_SENDING discards the send queue.

## Step 5 — Connection lifecycle + read loop (DONE)

`connectQuic()` and `QuicConnectionImpl` wire packet I/O, the frame layer, and
the stream manager over an injected `DatagramTransport`. The read loop turns
inbound datagrams into frames, dispatches each to the manager, and drains
pending stream sends back into outbound packets.

Tests: a fake datagram pair connects a client to a scripted peer; open +
accept streams; a peer CONNECTION_CLOSE tears the connection down.

## Step 6 — Packet protection (TODO)

Header protection + AEAD payload encryption (RFC 9000 §5) using keys derived
from the TLS handshake via `@browsercore/crypto`. This is the layer that makes
the data plane wire-ready.

Tests: protect then unprotect a packet round-trips; a tampered packet fails
decryption.

## Step 7 — TLS 1.3 handshake (TODO)

The QUIC handshake (RFC 9000 §19) over CRYPTO frames, driving the TLS 1.3
state machine to derive the QUIC key schedule. Out of scope until the crypto
package exposes the needed key schedule.

Tests: a scripted handshake completes and yields the expected key material.

## Definition of done

Checklist reflects test status, not implementation status — see step markers.

- [x] Varint encodes/decodes each form and selects the shortest length.
- [x] Packet headers parse/serialize for long + short forms; packet numbers round-trip.
- [x] Every QUIC frame type parses and serializes correctly.
- [x] Stream state machine covers reassembly, reset, stop_sending, and flow control.
- [x] Connection read loop dispatches frames and drains sends over a fake transport.
- [ ] Packet protection (header protection + AEAD) round-trips.
- [ ] TLS 1.3 handshake completes and derives the QUIC key schedule.
- [ ] Congestion controller + liveness PING.
- [ ] Connection migration + PATH_CHALLENGE / PATH_RESPONSE.
- [ ] Every test in `tests/` passes; `tsc --build` is clean.
