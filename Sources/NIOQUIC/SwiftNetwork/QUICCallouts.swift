//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import DequeModule
import NIOCore
import NIOQUICHelpers
@_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetwork

/// The calls a connection makes into NIO and consumer code on the stack's behalf, queued while the
/// stack holds the connection's event context and run once it's released.
///
/// SwiftNetwork's `NetworkContext.EventContext` is an exclusive token: acquiring it while it's held
/// traps. NIO's pipeline is synchronous and re-entrant: code NIOQUIC calls into (a handler reacting
/// to a `channelRead`, a promise callback, a stream initializer) can call straight back into
/// NIOQUIC, which then needs the token again. So NIOQUIC never makes such calls while the token is
/// held:
///
/// - Code that holds the token, recognisable by its `inout NetworkContext.EventContext` parameter
///   and including every witness the stack calls, updates NIOQUIC's own state and queues the call
///   with ``add(_:in:)`` instead of making it.
/// - Whoever acquired the token runs the queue once it's released. NIOQUIC's entry points acquire
///   through ``enter(as:_:)``, which runs the queue on the way out. Framework entry points that
///   acquire the token themselves (attaching flows and paths, metadata setters such as keep-alive)
///   are called through ``callFramework(_:)``, which runs what their witnesses queued. Otherwise
///   the stack acquires the token only inside the tasks it schedules on the connection's
///   `EventLoopBackedScheduler`, which runs the queue after each of them.
///
/// So NIO and consumer code only run with nothing held, NIOQUIC's entry points always acquire the
/// token afresh, and the queued calls run in order, in the event loop tick that queued them. A call
/// whose code enters the stack again (a handler's `flush()`, say) gets the calls that entry queues
/// before it returns; the rest of the queue runs after it.
///
/// Consumer code that still runs with the token held, because NIOQUIC needs its result there: the
/// connection ID and stateless reset token generators. They must not call into NIOQUIC.
///
/// There is one queue per `NetworkContext`, so one per connection.
@available(anyAppleOS 26, *)
final class QUICCallouts {
    private var queue: Deque<QUICCallout>

    #if DEBUG
    /// How many of ``enter(as:_:)``, ``callFramework(_:)`` and scheduler tasks are running.
    private var stackDepth: Int
    #endif

    init() {
        self.queue = []
        #if DEBUG
        self.stackDepth = 0
        #endif
    }

    #if DEBUG
    /// Whether the stack may hold the event context: inside ``enter(as:_:)``, ``callFramework(_:)``
    /// or a scheduler task. Debug builds check it when calls are queued and when the stack is
    /// entered, and in the stream channel's pipeline.
    var isInsideStack: Bool {
        self.stackDepth > 0
    }
    #endif

    /// Queues `callout` to run once the event context is released.
    ///
    /// Takes the event context only to show the caller holds it: whoever acquired it runs the queue.
    func add(_ callout: QUICCallout, in eventContext: inout NetworkContext.EventContext) {
        #if DEBUG
        assert(
            self.isInsideStack,
            "Callout queued where nothing runs the queue: call the framework through callFramework(_:)"
        )
        #endif
        self.queue.append(callout)
    }

    /// Runs `body` with the connection's event context, entering the stack as `instance`, then runs
    /// the calls queued meanwhile, before returning or rethrowing.
    ///
    /// Must be called with nothing held, as it is wherever NIO or consumer code calls into NIOQUIC.
    /// Enter as the NIOQUIC instance that makes the call, never as a framework instance it calls
    /// into: a down-call requires its callee to be idle, and entering as the callee makes it busy.
    @inline(__always)
    func enter<Instance: ProtocolInstance, Value, Failure: Error>(
        as instance: Instance,
        _ body: (inout NetworkContext.EventContext) throws(Failure) -> Value
    ) throws(Failure) -> Value {
        self.willEnterStack()
        defer {
            self.didLeaveStack()
            self.run()
        }
        return try instance.fromExternal(body)
    }

    /// Calls a framework entry point that acquires the event context itself, then runs the calls its
    /// witnesses queued meanwhile, before returning or rethrowing.
    ///
    /// Must be called with nothing held, like ``enter(as:_:)``.
    @inline(__always)
    func callFramework<Value, Failure: Error>(_ body: () throws(Failure) -> Value) throws(Failure) -> Value {
        self.willEnterStack()
        defer {
            self.didLeaveStack()
            self.run()
        }
        return try body()
    }

    /// Runs a task the stack scheduled, inside which it acquires the event context itself, then the
    /// calls queued meanwhile.
    func runStackTask(_ task: () -> Void) {
        self.willEnterStack()
        task()
        self.didLeaveStack()
        self.run()
    }

    /// Runs the queued calls, and those they queue in turn.
    func run() {
        #if DEBUG
        assert(!self.isInsideStack, "Queued callouts run only once the event context is released")
        #endif
        while !self.queue.isEmpty {
            // Take the batch, so that a call whose code enters the stack again runs only that
            // entry's calls before it returns.
            var batch = Deque<QUICCallout>()
            swap(&batch, &self.queue)
            while let callout = batch.popFirst() {
                callout.run(through: self)
            }
            // Keep the storage for the next batch, unless calls were queued meanwhile.
            if self.queue.isEmpty {
                swap(&batch, &self.queue)
            }
        }
    }

    @inline(__always)
    private func willEnterStack() {
        #if DEBUG
        assert(!self.isInsideStack, "Entering the stack while it may hold the event context")
        assert(self.queue.isEmpty, "Callouts left queued by an earlier stretch inside the stack")
        self.stackDepth += 1
        #endif
    }

    @inline(__always)
    private func didLeaveStack() {
        #if DEBUG
        self.stackDepth -= 1
        #endif
    }
}

/// A call into NIO or consumer code queued while the event context is held, or a framework entry
/// point that acquires the event context itself. See ``QUICCallouts``.
@available(anyAppleOS 26, *)
enum QUICCallout {
    /// The stream channel became active: `channelRegistered`, then `channelActive`.
    case streamActive(QUICChannelStreamHandler)
    /// The stream channel's buffered inbound bytes, as a `channelRead`.
    case streamRead(QUICChannelStreamHandler)
    /// The end of a burst of reads on the stream channel: `channelReadComplete`, then auto-read.
    case streamReadComplete(QUICChannelStreamHandler)
    /// `ChannelEvent.inputClosed` on the stream channel.
    case streamInputClosed(QUICChannelStreamHandler)
    /// `QUICStopSendingEvent` on the stream channel.
    case streamStopSending(QUICChannelStreamHandler, code: NIOQUICHelpers.QUICApplicationErrorCode)
    /// `errorCaught` on the stream channel.
    case streamError(QUICChannelStreamHandler, any Error)
    /// The stream channel closed: its close promise, `errorCaught` if there's an error, then
    /// `channelInactive` and `channelUnregistered` if it was active.
    case streamClosed(QUICChannelStreamHandler, promise: EventLoopPromise<Void>?, error: (any Error)?)
    /// A locally opened stream's outcome, for whoever opened it.
    case streamReady(
        (Result<(streamID: QUICStreamID, handler: QUICChannelStreamHandler), any Error>) -> Void,
        Result<(streamID: QUICStreamID, handler: QUICChannelStreamHandler), any Error>
    )
    /// Completes a promise.
    case completePromise(EventLoopPromise<Void>, Result<Void, any Error>)
    /// A call into the connection channel.
    case connection(any QUICConnectionCalloutTarget, QUICConnectionCallout)
    /// Sets the QUIC connection's keep-alive interval, in seconds. The setter is a framework entry
    /// point that acquires the event context itself.
    case setKeepalive(SwiftNetwork.QUICConnectionProtocol.QUICConnectionMetadata, seconds: UInt16)

    func run(through callouts: QUICCallouts) {
        switch self {
        case .streamActive(let stream):
            stream.deliverActive()
        case .streamRead(let stream):
            stream.deliverRead()
        case .streamReadComplete(let stream):
            stream.deliverReadComplete()
        case .streamInputClosed(let stream):
            stream.deliverInputClosed()
        case .streamStopSending(let stream, let code):
            stream.deliverStopSending(code: code)
        case .streamError(let stream, let error):
            stream.deliverError(error)
        case .streamClosed(let stream, let promise, let error):
            stream.deliverClose(promise: promise, error: error)
        case .streamReady(let onStreamReady, let result):
            onStreamReady(result)
        case .completePromise(let promise, let result):
            promise.completeWith(result)
        case .connection(let connection, let callout):
            connection.run(callout)
        case .setKeepalive(let metadata, let seconds):
            callouts.callFramework {
                metadata.setKeepalive(keepAlive: seconds)
            }
        }
    }
}

@available(anyAppleOS 26, *)
extension QUICCallout {
    /// The keep-alive interval in the whole seconds ``setKeepalive(_:seconds:)`` takes.
    ///
    /// SwiftNetwork reads `0` as "off" and `UInt16.max` as "its default interval", so an interval
    /// rounds down to whole seconds, but to at least one second and below `UInt16.max`: a
    /// sub-second interval must not turn keep-alives off.
    static func keepAliveSeconds(for interval: Duration) -> UInt16 {
        guard interval > .zero else {
            return 0
        }
        return UInt16(clamping: min(max(interval.components.seconds, 1), Int64(UInt16.max) - 1))
    }
}

/// A call into the connection channel. See ``QUICCallout/connection(_:_:)``.
@available(anyAppleOS 26, *)
enum QUICConnectionCallout {
    /// The handshake completed. The peer accepts datagrams up to the given size, none if it's zero.
    case handshakeCompleted(peerMaxDatagramFrameSize: Int)
    /// The connection closed, with an error or cleanly.
    case closed((any Error)?)
    /// The connection associated a new connection ID with itself: `QUICSCIDAssociatedEvent`.
    case connectionIDAssociated(QUICConnectionID)
    /// The connection retired one of its connection IDs: `QUICSCIDRetiredEvent`.
    case connectionIDRetired(QUICConnectionID)
    /// A datagram arrived on the connection's datagram flow, for a `channelRead`.
    case datagramRead(ByteBuffer)
    /// The connection's datagram flow failed, for an `errorCaught`.
    case datagramError(any Error)
}

/// The connection a ``QUICConnectionCallout`` runs on. `SwiftNetworkQUICConnection` is generic over
/// its consumer, so the queue refers to it through this.
@available(anyAppleOS 26, *)
protocol QUICConnectionCalloutTarget: AnyObject {
    func run(_ callout: QUICConnectionCallout)
}

/// A protocol instance that exists only to enter the stack on behalf of code with no instance of its
/// own: the stream table's operations, which act for streams that aren't `ProtocolInstance`s.
@available(anyAppleOS 26, *)
final class EventContextAnchor: ProtocolInstance {
    let context: NetworkContext
    var identifier: InstanceIdentifier
    var eventManager: ProtocolEventManager

    /// Registers with `context`, which acquires the event context: must be called with none held.
    init(context: NetworkContext) {
        self.context = context
        var eventManager = ProtocolEventManager()
        self.identifier = InstanceIdentifier(context: context, eventManager: &eventManager)
        self.eventManager = eventManager
    }

    /// Unregisters, so its event manager doesn't trap on deinit. Idempotent.
    func retire(through callouts: QUICCallouts) {
        if self.identifier.isNone { return }
        callouts.enter(as: self) { eventContext in
            self.unregisterEventManager(in: &eventContext)
        }
    }
}
