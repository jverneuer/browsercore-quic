/**
 * QUIC frame parser and serializer (RFC 9000 §12).
 *
 * Pure wire-format logic — no I/O. Frames are written into packets; the frame
 * layer does not own the packet or the transport. Each frame is encoded as its
 * type varint followed by type-specific fields. The reader functions consume
 * bytes from a pull-based source so they can be driven by a packet reassembly
 * buffer.
 *
 * STREAM frames (0x08–0x0f) are encoded with their off/len/fin flags folded
 * into the type byte; the reader/writer handle that transparently.
 */

import {
    QuicFrameType,
    STREAM_OFF_BIT,
    STREAM_LEN_BIT,
    STREAM_FIN_BIT,
    type QuicFrame,
    type QuicFrameTypeValue,
} from "../types.js";
import { decodeVarint, encodeVarint } from "./varint.js";
import { assertNever, concat, concatAll } from "../utils.js";

export {
    QuicFrameType,
    type QuicFrame,
    type QuicFrameTypeValue,
};

/** Serialize a single QUIC frame to wire bytes (type varint + fields). */
export function serializeFrame(frame: QuicFrame): Uint8Array {
    switch (frame.type) {
        case QuicFrameType.PADDING:
            return new Uint8Array([QuicFrameType.PADDING]);
        case QuicFrameType.PING:
            return new Uint8Array([QuicFrameType.PING]);

        case QuicFrameType.ACK:
        case QuicFrameType.ACK_ECN: {
            const body = concatAll([
                encodeVarint(frame.largestAck),
                encodeVarint(frame.ackDelay),
                encodeVarint(frame.ackRangeCount),
                encodeVarint(frame.firstAckRange),
                ...frame.ackRanges.flatMap((r) => [encodeVarint(r.gap), encodeVarint(r.ackRangeLength)]),
            ]);
            if (frame.type === QuicFrameType.ACK_ECN && frame.ecnCounts) {
                return concatAll([
                    encodeVarint(BigInt(QuicFrameType.ACK_ECN)),
                    body,
                    encodeVarint(frame.ecnCounts.ect0),
                    encodeVarint(frame.ecnCounts.ect1),
                    encodeVarint(frame.ecnCounts.ce),
                ]);
            }
            return concatAll([encodeVarint(BigInt(QuicFrameType.ACK)), body]);
        }

        case QuicFrameType.RESET_STREAM:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.streamId),
                encodeVarint(frame.errorCode),
                encodeVarint(frame.finalSize),
            ]);

        case QuicFrameType.STOP_SENDING:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.streamId),
                encodeVarint(frame.errorCode),
            ]);

        case QuicFrameType.CRYPTO:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.offset),
                encodeVarint(BigInt(frame.data.length)),
                frame.data,
            ]);

        case QuicFrameType.NEW_TOKEN:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(BigInt(frame.token.length)),
                frame.token,
            ]);

        case QuicFrameType.STREAM: {
            // Reconstruct the type byte with off/len/fin flags.
            let typeByte = QuicFrameType.STREAM;
            if (frame.offset > 0n) {
                typeByte |= STREAM_OFF_BIT;
            }
            // Length is always present in this encoding (simplification).
            typeByte |= STREAM_LEN_BIT;
            if (frame.fin) {
                typeByte |= STREAM_FIN_BIT;
            }
            const length = BigInt(frame.data.length);
            return concatAll([
                encodeVarint(BigInt(typeByte)),
                encodeVarint(frame.streamId),
                frame.offset > 0n ? encodeVarint(frame.offset) : new Uint8Array(0),
                encodeVarint(length),
                frame.data,
            ]);
        }

        case QuicFrameType.MAX_DATA:
            return concatAll([encodeVarint(BigInt(frame.type)), encodeVarint(frame.maximum)]);

        case QuicFrameType.MAX_STREAM_DATA:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.streamId),
                encodeVarint(frame.maximum),
            ]);

        case QuicFrameType.MAX_STREAMS_BIDI:
        case QuicFrameType.MAX_STREAMS_UNI:
            return concatAll([encodeVarint(BigInt(frame.type)), encodeVarint(frame.maximum)]);

        case QuicFrameType.DATA_BLOCKED:
            return concatAll([encodeVarint(BigInt(frame.type)), encodeVarint(frame.limit)]);

        case QuicFrameType.STREAM_DATA_BLOCKED:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.streamId),
                encodeVarint(frame.limit),
            ]);

        case QuicFrameType.STREAMS_BLOCKED_BIDI:
        case QuicFrameType.STREAMS_BLOCKED_UNI:
            return concatAll([encodeVarint(BigInt(frame.type)), encodeVarint(frame.limit)]);

        case QuicFrameType.NEW_CONNECTION_ID:
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.sequenceNumber),
                encodeVarint(frame.retirePriorTo),
                encodeVarint(BigInt(frame.connectionId.length)),
                frame.connectionId,
                frame.statelessResetToken,
            ]);

        case QuicFrameType.RETIRE_CONNECTION_ID:
            return concatAll([encodeVarint(BigInt(frame.type)), encodeVarint(frame.sequenceNumber)]);

        case QuicFrameType.PATH_CHALLENGE:
        case QuicFrameType.PATH_RESPONSE:
            return concatAll([encodeVarint(BigInt(frame.type)), frame.data]);

        case QuicFrameType.CONNECTION_CLOSE:
        case QuicFrameType.CONNECTION_CLOSE_APP: {
            // Per RFC 9000 §19.19 the frame-type field is always present; when the
            // caller omits it we encode 0 (no specific frame triggered the close).
            const reasonBytes = new TextEncoder().encode(frame.reason) as Uint8Array<ArrayBuffer>;
            return concatAll([
                encodeVarint(BigInt(frame.type)),
                encodeVarint(frame.errorCode),
                encodeVarint(frame.frameType ?? 0n),
                encodeVarint(BigInt(reasonBytes.length)),
                reasonBytes,
            ]);
        }

        case QuicFrameType.HANDSHAKE_DONE:
            return new Uint8Array([QuicFrameType.HANDSHAKE_DONE]);

        default:
            return assertNever(frame);
    }
}

/** Read frames from a pull-based byte source until it reports end-of-packet. */
export function readFrames(
    read: () => Promise<Uint8Array | null>,
): AsyncGenerator<QuicFrame, void, unknown> {
    return {
        [Symbol.asyncIterator]() {
            let buffer: Uint8Array = new Uint8Array(0);
            let done = false;

            async function fill(minBytes: number): Promise<boolean> {
                while (buffer.length < minBytes && !done) {
                    // eslint-disable-next-line no-await-in-loop — stream read: must buffer sequentially until minBytes satisfied
                    const chunk = await read();
                    if (chunk === null) {
                        done = true;
                        break;
                    }
                    buffer = concat(buffer, chunk);
                }
                return buffer.length >= minBytes;
            }

            async function readVarintFromBuffer(): Promise<bigint> {
                // Ensure at least one byte is buffered so the length prefix is
                // readable; fill() returns false only at end-of-stream. We then
                // pull any extra bytes a multi-byte varint needs.
                if (!(await fill(1))) {
                    throw new Error("unexpected end of frame data");
                }
                const first = buffer[0];
                if (first === undefined) {
                    // fill(1) returning true guarantees a byte is present; this is
                    // a defensive guard for the noUncheckedIndexedAccess narrowing.
                    throw new Error("unexpected end of frame data");
                }
                const length = 1 << ((first >> 6) & 0x03);
                if (!(await fill(length))) {
                    throw new Error("unexpected end of frame data");
                }
                const { value, length: consumed } = decodeVarint(buffer);
                buffer = buffer.subarray(consumed);
                return value;
            }

            async function readBytes(count: bigint): Promise<Uint8Array> {
                const n = Number(count);
                if (!(await fill(n))) {
                    throw new Error("unexpected end of frame data");
                }
                const out = buffer.subarray(0, n);
                buffer = buffer.subarray(n);
                return out;
            }

            async function parseOne(): Promise<QuicFrame> {
                const type = await readVarintFromBuffer();
                return decodeFrame(type, readVarintFromBuffer, readBytes);
            }

            return {
                next(): Promise<IteratorResult<QuicFrame>> {
                    return (async () => {
                        // Peek: is there any data left?
                        if (!(await fill(1))) {
                            return { done: true, value: undefined };
                        }
                        const frame = await parseOne();
                        return { done: false, value: frame };
                    })();
                },
            };
        },
    } as AsyncGenerator<QuicFrame, void, unknown>;
}

/** Decode a single frame given its type value and byte-reading helpers. */
export async function decodeFrame(
    type: bigint,
    readVarint: () => Promise<bigint>,
    readBytes: (count: bigint) => Promise<Uint8Array>,
): Promise<QuicFrame> {
    switch (type) {
        case BigInt(QuicFrameType.PADDING):
            return { type: QuicFrameType.PADDING };
        case BigInt(QuicFrameType.PING):
            return { type: QuicFrameType.PING };

        case BigInt(QuicFrameType.ACK): {
            const largestAck = await readVarint();
            const ackDelay = await readVarint();
            const ackRangeCount = await readVarint();
            const firstAckRange = await readVarint();
            const ackRanges: Array<{ gap: bigint; ackRangeLength: bigint }> = [];
            for (let i = 0n; i < ackRangeCount; i++) {
                // eslint-disable-next-line no-await-in-loop — ACK ranges are length-prefixed; must decode sequentially
                const gap = await readVarint();
                // eslint-disable-next-line no-await-in-loop — ACK ranges are length-prefixed; must decode sequentially
                const ackRangeLength = await readVarint();
                ackRanges.push({ gap, ackRangeLength });
            }
            return {
                type: QuicFrameType.ACK,
                largestAck,
                ackDelay,
                ackRangeCount,
                firstAckRange,
                ackRanges,
            };
        }

        case BigInt(QuicFrameType.ACK_ECN): {
            const largestAck = await readVarint();
            const ackDelay = await readVarint();
            const ackRangeCount = await readVarint();
            const firstAckRange = await readVarint();
            const ackRanges: Array<{ gap: bigint; ackRangeLength: bigint }> = [];
            for (let i = 0n; i < ackRangeCount; i++) {
                // eslint-disable-next-line no-await-in-loop — ACK_ECN ranges are length-prefixed; must decode sequentially
                const gap = await readVarint();
                // eslint-disable-next-line no-await-in-loop — ACK_ECN ranges are length-prefixed; must decode sequentially
                const ackRangeLength = await readVarint();
                ackRanges.push({ gap, ackRangeLength });
            }
            const ect0 = await readVarint();
            const ect1 = await readVarint();
            const ce = await readVarint();
            return {
                type: QuicFrameType.ACK_ECN,
                largestAck,
                ackDelay,
                ackRangeCount,
                firstAckRange,
                ackRanges,
                ecnCounts: { ect0, ect1, ce },
            };
        }

        case BigInt(QuicFrameType.RESET_STREAM): {
            const streamId = await readVarint();
            const errorCode = await readVarint();
            const finalSize = await readVarint();
            return { type: QuicFrameType.RESET_STREAM, streamId, errorCode, finalSize };
        }

        case BigInt(QuicFrameType.STOP_SENDING): {
            const streamId = await readVarint();
            const errorCode = await readVarint();
            return { type: QuicFrameType.STOP_SENDING, streamId, errorCode };
        }

        case BigInt(QuicFrameType.CRYPTO): {
            const offset = await readVarint();
            const length = await readVarint();
            const data = await readBytes(length);
            return { type: QuicFrameType.CRYPTO, offset, data };
        }

        case BigInt(QuicFrameType.NEW_TOKEN): {
            const length = await readVarint();
            const token = await readBytes(length);
            return { type: QuicFrameType.NEW_TOKEN, token };
        }

        // STREAM frames: type byte 0x08..0x0f.
        case 0x08n:
        case 0x09n:
        case 0x0an:
        case 0x0bn:
        case 0x0cn:
        case 0x0dn:
        case 0x0en:
        case 0x0fn: {
            const typeByte = Number(type);
            const streamId = await readVarint();
            // The serializer always sets the offset bit when offset > 0 and always
            // sets the length bit, so both fields are always present on the wire.
            const offset = typeByte & STREAM_OFF_BIT ? await readVarint() : 0n;
            const length = await readVarint();
            const data = await readBytes(length);
            const fin = (typeByte & STREAM_FIN_BIT) !== 0;
            return { type: QuicFrameType.STREAM, streamId, offset, data, fin };
        }

        case BigInt(QuicFrameType.MAX_DATA):
            return { type: QuicFrameType.MAX_DATA, maximum: await readVarint() };

        case BigInt(QuicFrameType.MAX_STREAM_DATA): {
            const streamId = await readVarint();
            const maximum = await readVarint();
            return { type: QuicFrameType.MAX_STREAM_DATA, streamId, maximum };
        }

        case BigInt(QuicFrameType.MAX_STREAMS_BIDI):
            return { type: QuicFrameType.MAX_STREAMS_BIDI, maximum: await readVarint() };

        case BigInt(QuicFrameType.MAX_STREAMS_UNI):
            return { type: QuicFrameType.MAX_STREAMS_UNI, maximum: await readVarint() };

        case BigInt(QuicFrameType.DATA_BLOCKED):
            return { type: QuicFrameType.DATA_BLOCKED, limit: await readVarint() };

        case BigInt(QuicFrameType.STREAM_DATA_BLOCKED): {
            const streamId = await readVarint();
            const limit = await readVarint();
            return { type: QuicFrameType.STREAM_DATA_BLOCKED, streamId, limit };
        }

        case BigInt(QuicFrameType.STREAMS_BLOCKED_BIDI):
            return { type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: await readVarint() };

        case BigInt(QuicFrameType.STREAMS_BLOCKED_UNI):
            return { type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: await readVarint() };

        case BigInt(QuicFrameType.NEW_CONNECTION_ID): {
            const sequenceNumber = await readVarint();
            const retirePriorTo = await readVarint();
            const length = await readVarint();
            const connectionId = await readBytes(length);
            const statelessResetToken = await readBytes(16n);
            return {
                type: QuicFrameType.NEW_CONNECTION_ID,
                sequenceNumber,
                retirePriorTo,
                connectionId,
                statelessResetToken,
            };
        }

        case BigInt(QuicFrameType.RETIRE_CONNECTION_ID):
            return {
                type: QuicFrameType.RETIRE_CONNECTION_ID,
                sequenceNumber: await readVarint(),
            };

        case BigInt(QuicFrameType.PATH_CHALLENGE):
            return { type: QuicFrameType.PATH_CHALLENGE, data: await readBytes(8n) };

        case BigInt(QuicFrameType.PATH_RESPONSE):
            return { type: QuicFrameType.PATH_RESPONSE, data: await readBytes(8n) };

        case BigInt(QuicFrameType.CONNECTION_CLOSE):
        case BigInt(QuicFrameType.CONNECTION_CLOSE_APP): {
            const errorCode = await readVarint();
            // Frame type field: present only if there are more bytes. We read a
            // varint frame-type then a length-prefixed reason; if the remaining
            // data doesn't parse cleanly, fall back.
            const frameType = await readVarint();
            const reasonLength = await readVarint();
            const reasonBytes = await readBytes(reasonLength);
            const reason = new TextDecoder().decode(reasonBytes);
            return {
                type: type === BigInt(QuicFrameType.CONNECTION_CLOSE)
                    ? QuicFrameType.CONNECTION_CLOSE
                    : QuicFrameType.CONNECTION_CLOSE_APP,
                errorCode,
                frameType,
                reason,
            };
        }

        case BigInt(QuicFrameType.HANDSHAKE_DONE):
            return { type: QuicFrameType.HANDSHAKE_DONE };

        default:
            // Unknown frame types: per RFC 9000, frames of unknown type in
            // non-1-RTT packets are a connection error; in 1-RTT packets they
            // MAY be ignored. We surface a generic frame so callers can decide.
            return { type: QuicFrameType.PADDING };
    }
}
