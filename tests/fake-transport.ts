/**
 * A scriptable in-memory DatagramTransport for testing the QUIC connection
 * without a real network. It implements the `DatagramTransport` interface from
 * this package over internal datagram queues so a test can push datagrams the
 * client "receives" and inspect datagrams the client "sent".
 *
 * It is NOT a real transport — it exists only to drive connection.test.ts.
 */

import type { EventProvider } from "@browsercore/contracts";
import type { DatagramTransport, UdpAddress } from "../src/types.js";

/** A fixed IPv4 loopback address for tests. */
export const LOCAL_ADDR: UdpAddress = { address: "127.0.0.1", port: 4433, family: 4 };
export const PEER_ADDR: UdpAddress = { address: "127.0.0.1", port: 8443, family: 4 };

/** A single buffered datagram. */
interface Envelope {
    readonly data: Uint8Array;
    readonly from: UdpAddress;
}

/**
 * A pair of connected fake datagram transports: everything sent by one is
 * receivable by the other. Used to connect a client to a scripted "peer".
 */
export function createFakeDatagramPair(): {
    client: FakeDatagramTransport;
    server: FakeDatagramTransport;
} {
    const client = new FakeDatagramTransport("client", PEER_ADDR);
    const server = new FakeDatagramTransport("server", LOCAL_ADDR);
    client._peer = server;
    server._peer = client;
    return { client, server };
}

/** Minimal in-memory EventProvider for tests — decouples from node:events. */
export function testEventProvider(): EventProvider {
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    return {
        on(event, listener) {
            if (!listeners.has(event)) listeners.set(event, new Set());
            listeners.get(event)!.add(listener);
        },
        once(event, listener) {
            const wrapped = (...args: unknown[]) => {
                listeners.get(event)?.delete(wrapped);
                listener(...args);
            };
            this.on(event, wrapped);
        },
        off(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        removeListener(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        emit(event, ...args) {
            const set = listeners.get(event);
            if (!set || set.size === 0) return false;
            for (const l of [...set]) l(...args);
            return true;
        },
        listenerCount(event) {
            return listeners.get(event)?.size ?? 0;
        },
        removeAllListeners(event) {
            if (event) listeners.delete(event);
            else listeners.clear();
        },
    };
}

export class FakeDatagramTransport implements DatagramTransport {
    public readonly id: string;
    private readonly _peer: FakeDatagramTransport | undefined;
    private readonly _localAddr: UdpAddress;
    private _closed = false;
    /** Datagrams sent by this side, buffered for the peer to recv(). */
    private readonly _outbox: Envelope[] = [];
    /** Waiters blocked on a recv() when the outbox was empty. */
    private _pendingRecv: ((env: Envelope) => void) | undefined;
    private _pendingRecvReject: ((err: Error) => void) | undefined;

    public constructor(id: string, localAddr: UdpAddress, peer?: FakeDatagramTransport) {
        this.id = id;
        this._localAddr = localAddr;
        this._peer = peer;
    }

    public send(data: Uint8Array, _address: UdpAddress): Promise<void> {
        if (this._closed) return Promise.reject(new Error(`transport ${this.id} is closed`));
        const peer = this._peer;
        if (peer !== undefined) {
            peer._deliver(data);
            return Promise.resolve();
        }
        // No peer: buffer for a test to drain via sentDatagrams().
        this._outbox.push({ data, from: this._localAddr });
        return Promise.resolve();
    }

    public recv(): Promise<{ readonly data: Uint8Array; readonly from: UdpAddress }> {
        if (this._closed) return Promise.reject(new Error(`transport ${this.id} is closed`));
        if (this._outbox.length > 0) {
            const env = this._outbox.shift()!;
            return Promise.resolve(env);
        }
        return new Promise<{ readonly data: Uint8Array; readonly from: UdpAddress }>((resolve, reject) => {
            this._pendingRecv = resolve;
            this._pendingRecvReject = reject;
        });
    }

    public close(reason?: { readonly kind: string }): Promise<void> {
        if (this._closed) return Promise.resolve();
        this._closed = true;
        const rejecter = this._pendingRecvReject;
        if (rejecter !== undefined) {
            this._pendingRecv = undefined;
            this._pendingRecvReject = undefined;
            rejecter(new Error(`transport closed: ${reason?.kind ?? "unknown"}`));
        }
        return Promise.resolve();
    }

    /** True once close() has been called. */
    public get isClosed(): boolean {
        return this._closed;
    }

    /** Push a datagram into this side's recv queue (simulating data arriving). */
    private _deliver(data: Uint8Array): void {
        const env: Envelope = { data, from: this._peer?._localAddr ?? this._localAddr };
        const pending = this._pendingRecv;
        if (pending !== undefined) {
            this._pendingRecv = undefined;
            this._pendingRecvReject = undefined;
            pending(env);
        } else {
            this._outbox.push(env);
        }
    }
}
