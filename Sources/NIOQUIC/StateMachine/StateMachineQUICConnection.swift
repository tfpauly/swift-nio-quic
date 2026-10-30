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
import Logging
import NIOCore
import NIOQUICHelpers
@_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetwork
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// A datagram's buffer, which the connection builds its packet in.
///
/// The standalone protocol asks the driver for the frames it builds datagrams in. Each is a
/// `ByteBuffer` the driver hands out (wrapped by a `Frame`, which owns this box), and the finished
/// datagram goes to NIO as that same buffer, with the packet's offset and length.
@available(anyAppleOS 26, *)
final class OutputDatagram {
    var buffer: ByteBuffer

    init(buffer: ByteBuffer) {
        self.buffer = buffer
    }

    /// A frame over `size` bytes of a new buffer.
    static func makeFrame(size: Int, allocator: ByteBufferAllocator) -> Frame {
        var buffer = allocator.buffer(capacity: size)
        // Mark the whole capacity as in use: the frame wraps all of it, and the packet's offset and
        // length are set when the datagram is taken back.
        buffer.writeWithUnsafeMutableBytes(minimumWritableBytes: size) { _ in size }
        let box = OutputDatagram(buffer: buffer)
        let pointer = box.buffer.withUnsafeMutableReadableBytes { $0 }
        return Frame(customBuffer: pointer, owner: box)
    }

    /// Takes the datagram out of a finished frame, without copying it if the frame is one of ours.
    static func datagram(from frame: borrowing Frame, allocator: ByteBufferAllocator) -> ByteBuffer? {
        let length = frame.unclaimedLength
        guard length > 0 else { return nil }
        var base: UnsafeMutableRawPointer?
        var owned: OutputDatagram?
        switch frame.buffer {
        case .customOwner(let pointer, let owner):
            base = pointer.baseAddress
            // The owner is the box this file made when the frame is one of ours, which its class says.
            if ObjectIdentifier(type(of: owner)) == ObjectIdentifier(OutputDatagram.self) {
                owned = unsafeDowncast(owner, to: OutputDatagram.self)
            }
        default:
            break
        }
        if let owned, let base,
            let start = frame.span?.withUnsafeBufferPointer({ UnsafeRawPointer($0.baseAddress) })
        {
            let offset = start - UnsafeRawPointer(base)
            owned.buffer.moveReaderIndex(to: offset)
            owned.buffer.moveWriterIndex(to: offset + length)
            return owned.buffer
        }
        var buffer = allocator.buffer(capacity: length)
        frame.span?.withUnsafeBufferPointer { _ = buffer.writeBytes($0) }
        return buffer
    }
}

/// A QUIC connection driven directly from NIO through SwiftNetwork's `StandaloneQUICConnection`:
/// a protocol that owns its own event context, with no linkages, no call-out queue and no
/// scheduler for NIO to implement.
///
/// NIO feeds it datagrams and the time, collects the datagrams it queued, drains its events, and
/// arms one scheduled task for the deadline it asks for.
@available(anyAppleOS 26, *)
final class StateMachineQUICConnection<Consumer: QUICStreamConsumer & ~Copyable> {
    private var quic: StandaloneQUICConnection
    private let environment: StandaloneEnvironment
    let role: Role
    let localAddress: SocketAddress
    /// The address of the active path, which the channel reports.
    let remoteAddress: SendableAddress
    private let eventLoop: any EventLoop
    private let allocator: ByteBufferAllocator
    private var logger: Logger

    /// The channel, once it was created; dropped when the channel goes inactive.
    internal var channelView: QUICConnectionChannel<Consumer>.ConnectionView?

    /// The stream table the consumer works on.
    private(set) var streamTable: QUICStreamTable<Consumer>?

    /// Datagrams received in the current read loop, processed on `receivePacketsComplete`.
    private var inbound: Deque<AddressedEnvelope<ByteBuffer>> = []

    /// The paths a server knows, by the client address they lead to, in the order they were added;
    /// the handshake's path first. A client only has the one to the server.
    private var paths: [(address: SocketAddress, id: StandalonePathID)]

    /// The most paths a server keeps.
    static var maximumPaths: Int { 4 }
    private var inReadLoop = false
    /// Whether the connection was told its outbound data is batched.
    private var batching = false

    private var timer: Scheduled<Void>?
    private var timerDeadline: NetworkClock.Instant?

    /// The streams, by the flow the stack's events name.
    private var flows = StandaloneFlowWindow()

    /// Whether a drain of the connection's output is scheduled for the next loop tick.
    private var drainScheduled = false

    /// Whether the channel was told the handshake completed.
    private var reportedHandshake = false
    /// Whether the channel was told the connection closed.
    private var reportedClose = false
    /// Whether the close was initiated locally, through `close(...)`.
    private var closedLocally = false
    /// Whether the connection reported its disconnect: it needs no more driving.
    private(set) var isClosed = false

    /// Where the connection sends once its channel is gone, while it closes or drains.
    private var closingTransport: QUICHandler<Consumer>.ChildView?
    /// Runs when the connection closed after the channel went away; the handler stops routing to the
    /// connection. Holds the handler, which holds the connection, until then.
    private var onClosedWithoutChannel: (() -> Void)?

    /// The largest UDP payload sent.
    private let maximumDatagramSize: Int

    #if DEBUG
    /// Runs when the connection is released, so tests can check that nothing keeps it alive.
    var _forTesting_onDeinit: (() -> Void)?

    deinit {
        self._forTesting_onDeinit?()
    }

    /// The congestion window, in bytes. The standalone protocol doesn't expose it.
    var _forTesting_congestionWindow: Int {
        0
    }

    /// The paths the driver keeps.
    var _forTesting_pathCount: Int {
        self.paths.count
    }

    /// The largest UDP payload the connection sends.
    var _forTesting_maximumDatagramSize: Int {
        self.maximumDatagramSize
    }
    #endif

    private init(
        quic: consuming StandaloneQUICConnection,
        environment: StandaloneEnvironment,
        maximumDatagramSize: Int,
        role: Role,
        localAddress: SocketAddress,
        remoteAddress: SocketAddress,
        eventLoop: any EventLoop,
        logger: Logger
    ) {
        self.paths = [(remoteAddress, quic.primaryPath)]
        self.quic = quic
        self.environment = environment
        self.maximumDatagramSize = maximumDatagramSize
        self.role = role
        self.localAddress = localAddress
        self.remoteAddress = SendableAddress(remoteAddress)
        self.eventLoop = eventLoop
        self.allocator = ByteBufferAllocator()
        self.logger = logger
    }

    /// The QUIC options of a connection.
    private static func makeOptions(
        _ configuration: QUICConfiguration,
        role: Role,
        sourceConnectionID: QUICConnectionID,
        serverName: String,
        asyncVerifier: AsyncVerifier?,
        authenticator: Authenticator?,
        statelessResetToken: SwiftNetwork.QUICStatelessResetToken?
    ) throws -> ProtocolOptions<QUICProtocol> {
        let quicOptions = try QUICStreamProtocol.options(from: configuration)
        switch role {
        case .client:
            quicOptions.connectionOptions.forceVersionNegotiation = configuration.forceVersionNegotiation
            quicOptions.tlsOptions = try .clientOptions(
                from: configuration,
                asyncVerifier: asyncVerifier,
                serverName: serverName
            )
        case .server:
            guard let authConfig = configuration.authenticationConfiguration else {
                throw QUICError.tlsConfigurationIncomplete
            }
            quicOptions.connectionOptions.retry = configuration.sendRetry
            quicOptions.tlsOptions = try .serverOptions(
                from: configuration,
                authConfig: authConfig,
                authenticator: authenticator,
                serverName: serverName
            )
        }
        // '!' is okay: the `options(...)` call above throws if this isn't set.
        let perProtocolOptions = quicOptions.perProtocolOptions!
        // The driver routes no spare connection IDs.
        perProtocolOptions.quicConnectionOptions.disableAutomaticNewConnectionIDs = true
        if let statelessResetToken, sourceConnectionID.length > 0, role == .server {
            perProtocolOptions.quicConnectionOptions.initialStatelessResetToken = statelessResetToken
        }
        sourceConnectionID.withUnsafeBufferPointer { bufferPointer in
            perProtocolOptions.quicConnectionOptions.sourceConnectionID = Array(bufferPointer)
        }
        return quicOptions
    }

    static func client(
        configuration: QUICConfiguration,
        sourceConnectionID: QUICConnectionID,
        serverName: String?,
        asyncVerifier: AsyncVerifier?,
        localAddress: SocketAddress,
        remoteAddress: SocketAddress,
        eventLoop: any EventLoop,
        logger: Logger
    ) throws -> StateMachineQUICConnection<Consumer> {
        guard let serverName else {
            throw QUICError.tlsConfigurationIncomplete
        }
        let options = try Self.makeOptions(
            configuration,
            role: .client,
            sourceConnectionID: sourceConnectionID,
            serverName: serverName,
            asyncVerifier: asyncVerifier,
            authenticator: nil,
            statelessResetToken: nil
        )
        return try Self.make(
            options: options,
            configuration: configuration,
            role: .client,
            localAddress: localAddress,
            remoteAddress: remoteAddress,
            eventLoop: eventLoop,
            logger: logger
        )
    }

    static func server(
        configuration: QUICConfiguration,
        sourceConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        peerConnectionID: QUICConnectionID?,
        statelessResetTokenGenerator: any QUICStatelessResetToken.Generator,
        authenticator: Authenticator?,
        localAddress: SocketAddress,
        remoteAddress: SocketAddress,
        eventLoop: any EventLoop,
        logger: Logger
    ) throws -> StateMachineQUICConnection<Consumer> {
        guard let serverName = configuration.serverName else {
            throw QUICError.tlsConfigurationIncomplete
        }
        let options = try Self.makeOptions(
            configuration,
            role: .server,
            sourceConnectionID: sourceConnectionID,
            serverName: serverName,
            asyncVerifier: nil,
            authenticator: authenticator,
            statelessResetToken: sourceConnectionID.length > 0
                ? statelessResetTokenGenerator.token(for: sourceConnectionID).token : nil
        )
        return try Self.make(
            options: options,
            configuration: configuration,
            role: .server,
            localAddress: localAddress,
            remoteAddress: remoteAddress,
            eventLoop: eventLoop,
            logger: logger
        )
    }

    private static func make(
        options: ProtocolOptions<QUICProtocol>,
        configuration: QUICConfiguration,
        role: Role,
        localAddress: SocketAddress,
        remoteAddress: SocketAddress,
        eventLoop: any EventLoop,
        logger: Logger
    ) throws -> StateMachineQUICConnection<Consumer> {
        let environment = StandaloneEnvironment(
            identifier: "swift-nio-quic-standalone-\(role.description)",
            now: Self.now
        )
        let packetSize = max(configuration.initialPacketSize.size(forClientInitial: nil), 1200)
        let outputAllocator = ByteBufferAllocator()
        environment.maximumOutputSize = packetSize
        environment.setOutputFrameProvider { size in
            OutputDatagram.makeFrame(size: size, allocator: outputAllocator)
        }
        let quic = try StandaloneQUICConnection(
            options: options,
            isServer: role == .server,
            local: localAddress.toEndpoint(),
            remote: remoteAddress.toEndpoint(),
            environment: environment,
            releasesFlowsOnDisconnect: true
        )
        let connection = StateMachineQUICConnection(
            quic: quic,
            environment: environment,
            maximumDatagramSize: packetSize,
            role: role,
            localAddress: localAddress,
            remoteAddress: remoteAddress,
            eventLoop: eventLoop,
            logger: logger
        )
        connection.makeStreamTable(configuration: configuration)
        connection.installWorkAvailableHandler()
        connection.quic.connect()
        connection.afterUpdate()
        return connection
    }

    private func makeStreamTable(configuration: QUICConfiguration) {
        let table = QUICStreamTable<Consumer>(role: self.role, stateMachine: self)
        table.receiveWindows = ReceiveWindows(configuration)
        self.streamTable = table
    }

    /// What the work-available handler runs.
    ///
    /// Another thread (an asynchronous certificate verification) may ask for a turn; the handler
    /// reaches the connection through this target, which `dropChannelReferences()` clears, so the
    /// environment does not keep the connection alive.
    private final class WorkTarget {
        var connection: StateMachineQUICConnection?

        init(_ connection: StateMachineQUICConnection) {
            self.connection = connection
        }
    }

    private var workTarget: WorkTarget?

    private func installWorkAvailableHandler() {
        let eventLoop = self.eventLoop
        let target = WorkTarget(self)
        self.workTarget = target
        let loopBound = NIOLoopBound(target, eventLoop: eventLoop)
        self.environment.scheduler.onWorkAvailable = {
            eventLoop.execute {
                guard let connection = loopBound.value.connection else { return }
                connection.afterUpdate()
            }
        }
    }

    // MARK: Clock

    static var now: NetworkClock.Instant {
        NetworkClock.Instant.zero.advanced(by: .microseconds(Int64(NIODeadline.now().uptimeNanoseconds / 1000)))
    }

    private static func deadline(for instant: NetworkClock.Instant) -> NIODeadline {
        let nanoseconds = NetworkClock.Instant.zero.duration(to: instant).nanoseconds
        return .uptimeNanoseconds(UInt64(max(0, nanoseconds)))
    }

    // MARK: Driver

    func setDriver(_ channel: QUICConnectionChannel<Consumer>) {
        self.channelView = channel.connectionView
        // The cycle through `outOfBandDrain` is broken in `dropChannelReferences()`.
        self.streamTable?.outOfBandDrain = {
            self.channelView?.drainStreams()
        }
    }

    var isTerminating: Bool {
        self.closedLocally || self.isClosed
    }

    @discardableResult
    func receivePacket(_ envelope: AddressedEnvelope<ByteBuffer>) -> Int {
        if !self.inReadLoop {
            self.inReadLoop = true
            self.streamTable?.inReadLoop = true
            self.setBatching(true)
        }
        self.inbound.append(envelope)
        return envelope.data.readableBytes
    }

    func receivePacketsComplete() {
        self.environment.scheduler.advance(to: Self.now)
        // Hand the connection the whole read loop's datagrams at once, per path.
        var batch = FrameArray(capacity: max(self.inbound.count, 1))
        var batchPath: StandalonePathID?
        while var envelope = self.inbound.popFirst() {
            let path = self.path(for: envelope.remoteAddress)
            if let current = batchPath, current != path {
                self.quic.receiveFromBelow(path: current, batch.drainArray())
            }
            batchPath = path
            Self.append(&envelope.data, to: &batch)
        }
        if let path = batchPath, !batch.isEmpty {
            self.quic.receiveFromBelow(path: path, batch.drainArray())
        }
        self.afterUpdate()
    }

    /// Adds the datagram to `frames` without copying its storage.
    private static func append(_ buffer: inout ByteBuffer, to frames: inout FrameArray) {
        buffer.withUnsafeMutableReadableBytesWithStorageManagement2 { pointer, owner in
            frames.add(frame: Frame(customBuffer: pointer, owner: owner))
        }
    }

    /// Tells the connection whether the application batches its outbound data, so it packs a
    /// batch's data into as few datagrams as it can.
    private func setBatching(_ enabled: Bool) {
        guard self.batching != enabled else { return }
        self.batching = enabled
        self.quic.applicationEvent(enabled ? .outboundDataBatchStart : .outboundDataBatchEnd)
    }

    // MARK: Paths

    /// The path for a datagram from `address`, added if it is new.
    private func path(for address: SocketAddress) -> StandalonePathID {
        // A client only talks to the server's address.
        guard self.role == .server else { return self.quic.primaryPath }
        if let path = self.paths.first(where: { $0.address == address }) {
            return path.id
        }
        if self.paths.count >= Self.maximumPaths {
            // Drop the oldest path other than the handshake's.
            self.paths.remove(at: 1)
        }
        let local = self.localAddress.toEndpoint()
        guard let id = try? self.quic.addPath(local: local, remote: address.toEndpoint()) else {
            return self.quic.primaryPath
        }
        self.paths.append((address, id))
        return id
    }

    func exitReadLoop() {
        self.inReadLoop = false
        self.streamTable?.inReadLoop = false
        self.setBatching(false)
    }

    /// Runs the timers that are due, delivers the connection's events and re-arms the timer.
    private func afterUpdate() {
        self.environment.turn(now: Self.now)
        self.processEvents()
        if !self.inReadLoop {
            if let channelView = self.channelView {
                channelView.drainOutbound()
            } else if let transport = self.closingTransport {
                self.drainPacketsToSend(to: transport)
                transport.flush()
            }
        }
        self.rescheduleTimer()
    }

    private func processEvents() {
        while let event = self.environment.nextEvent() {
            switch event {
            case .connected(nil):
                if !self.reportedHandshake {
                    self.reportedHandshake = true
                    self.channelView?.handshakeCompleted(peerMaxDatagramFrameSize: 0)
                }
            case .connected(let flow?):
                self.flowConnected(flow)
            case .newInboundFlow(let flow, let streamID):
                self.newInboundFlow(flow, streamID: streamID)
            case .inboundDataAvailable(let flow?):
                self.mark(flow, .readable)
            case .outboundRoomAvailable(let flow?):
                self.mark(flow, .writable)
            case .inboundAborted(let flow?, let error):
                if let handle = self.flows[flow]?.handle, let code = Self.applicationErrorCode(error) {
                    self.streamTable?.peerResetStream(handle, code: code)
                }
            case .outboundAborted(let flow?, let error):
                if let handle = self.flows[flow]?.handle, let code = Self.applicationErrorCode(error) {
                    self.streamTable?.peerStoppedSending(handle, code: code)
                }
            case .disconnected(let flow?, let error):
                self.flowDisconnected(flow, error: error)
            case .disconnected(nil, let error):
                self.connectionClosed(error: error)
            case .outboundDataReady:
                ()
            case .network, .inboundDataAvailable(nil), .outboundRoomAvailable(nil),
                .inboundAborted(nil, _), .outboundAborted(nil, _):
                ()
            }
        }
    }

    private static func applicationErrorCode(_ error: NetworkError?) -> QUICApplicationErrorCode? {
        switch error?.quicApplicationError {
        case .some(let code) where code >= 0:
            return QUICApplicationErrorCode(UInt64(code))
        case .some, .none:
            return nil
        }
    }

    // MARK: Flow events

    private func mark(_ flow: StandaloneFlowID, _ events: QUICStreamEvents) {
        guard let handle = self.flows[flow]?.handle else { return }
        self.streamTable?.markReady(handle: handle, events: events)
    }

    /// A locally opened stream got its ID.
    private func flowConnected(_ flowID: StandaloneFlowID) {
        guard let flow = self.flows[flowID], flow.streamID == nil, let handle = flow.handle else { return }
        guard let metadata = self.quic.getMetadata(flow: flowID) as ProtocolMetadata<QUICProtocol>?,
            let streamID = metadata.streamID
        else { return }
        flow.streamID = streamID
        self.streamTable?.assignID(NIOQUICHelpers.QUICStreamID(rawValue: streamID), to: handle)
        self.streamTable?.markReady(handle: handle, events: .opened)
    }

    /// The peer opened a stream. The event carries the stream ID, so nothing is asked.
    private func newInboundFlow(_ flowID: StandaloneFlowID, streamID: UInt64) {
        guard let table = self.streamTable else {
            self.quic.teardown(flow: flowID)
            return
        }
        let quicStreamID = NIOQUICHelpers.QUICStreamID(rawValue: streamID)
        let flow = StandaloneStreamFlow(flowID: flowID)
        flow.streamID = streamID
        let handle = table.insertSlot(id: quicStreamID, state: nil, flow: flow)
        flow.handle = handle
        self.flows.insert(flow)
        table.assignID(quicStreamID, to: handle)
        table.markReady(handle: handle, events: [.opened, .readable])
    }

    private func flowDisconnected(_ flowID: StandaloneFlowID, error: NetworkError?) {
        guard let flow = self.flows[flowID] else { return }
        if let handle = flow.handle {
            self.streamTable?.streamDisconnected(handle, error: error)
        }
        // The connection releases the flow as it reports the disconnect: nothing to tear down.
        self.flows.remove(flow.flowID)
        if !flow.pending.isEmpty { flow.pending.finalizeAllFramesAsFailed() }
    }

    private func release(_ flow: StandaloneStreamFlow) {
        guard self.flows[flow.flowID] != nil else { return }
        self.flows.remove(flow.flowID)
        if !flow.pending.isEmpty { flow.pending.finalizeAllFramesAsFailed() }
        self.quic.teardown(flow: flow.flowID)
    }

    // MARK: Closing

    /// The connection reported its disconnect: nothing is left to drive, and it can be released.
    private func connectionClosed(error: NetworkError?) {
        self.timer?.cancel()
        self.timer = nil
        self.timerDeadline = nil
        self.isClosed = true
        self.logger.debug("Connection closed", metadata: ["quic.close.error": "\(String(describing: error))"])
        self.reportClose(error: error)
        self.closingTransport = nil
        if let onClosedWithoutChannel = self.onClosedWithoutChannel {
            self.onClosedWithoutChannel = nil
            onClosedWithoutChannel()
        }
    }

    /// Tells the channel, once, that the connection closed, which fails its streams with the
    /// reason.
    private func reportClose(error: NetworkError?) {
        guard !self.reportedClose else { return }
        self.reportedClose = true
        var reported: (any Error)?
        if !self.closedLocally, let error, !error.isIdleTimeout {
            if let code = error.quicTransportError, code != 0 {
                reported = QUICConnectionError(reason: error.description, isApplication: false, code: UInt64(code))
            } else if let code = error.quicApplicationError, code != 0 {
                reported = QUICConnectionError(reason: error.description, isApplication: true, code: UInt64(code))
            } else if error.quicApplicationError == nil, error.quicTransportError == nil {
                reported = QUICConnectionError(reason: error.description, isApplication: false, code: 0)
            }
        }
        self.channelView?.connectionClosed(error: reported)
    }

    // MARK: Timer

    private func rescheduleTimer() {
        guard let deadline = self.environment.nextTimerDeadline else { return }
        // Rescheduling a NIO task is expensive. Keep an armed timer that fires no later than
        // needed: if it fires early, `timerFired` re-arms it for the real deadline.
        if let current = self.timerDeadline, self.timer != nil, current <= deadline {
            return
        }
        self.timer?.cancel()
        self.timerDeadline = deadline
        self.timer = self.eventLoop.assumeIsolated().scheduleTask(deadline: Self.deadline(for: deadline)) {
            self.timerFired()
        }
    }

    private func timerFired() {
        self.timer = nil
        self.timerDeadline = nil
        self.afterUpdate()
    }

    // MARK: Output

    /// Makes sure output produced outside a read loop, such as a stream write from application code,
    /// is sent: the read loop drains on its own when it ends.
    private func outputProduced() {
        guard !self.inReadLoop, !self.drainScheduled, let channelView = self.channelView else { return }
        self.drainScheduled = true
        channelView.drainOutbound()
    }

    func drainPacketsToSend(to transport: some QUICTransport) {
        self.drainScheduled = false
        self.environment.scheduler.advance(to: Self.now)
        self.environment.turn()
        self.processEvents()
        for index in self.paths.indices {
            let (address, path) = self.paths[index]
            var frames = self.quic.takeOutbound(path: path)
            frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
                if let datagram = OutputDatagram.datagram(from: frame, allocator: self.allocator) {
                    transport.writeDatagram(AddressedEnvelope(remoteAddress: address, data: datagram), promise: nil)
                }
                frame.finalize(success: true)
                return .removeFrameAndContinue
            }
        }
        self.rescheduleTimer()
    }

    // MARK: Close

    func close(isApplicationClose: Bool, errorCode: Int64, reason: String) -> Bool {
        guard !self.isTerminating else {
            self.processEvents()
            return false
        }
        self.logger.debug(
            "Closing connection",
            metadata: [
                "quic.close.errorCode": "\(errorCode)", "quic.close.isApplication": "\(isApplicationClose)",
                "quic.close.reason": "\(reason)",
            ]
        )
        self.closedLocally = true
        let error: NetworkError?
        if isApplicationClose {
            error = NetworkError(quicApplicationError: errorCode, reason: reason)
        } else if let transportError = QUICTransportError(UInt64(errorCode), reason) {
            error = NetworkError(quicTransportError: transportError)
        } else {
            error = nil
        }
        self.environment.scheduler.advance(to: Self.now)
        self.quic.disconnect(error: error)
        self.environment.turn()
        self.processEvents()
        self.rescheduleTimer()
        // Report the close right away: the channel drains the CONNECTION_CLOSE and fires inactive
        // once this returns. The connection keeps answering the peer for the closing period on its
        // own timer.
        if !self.reportedClose {
            self.reportedClose = true
            self.channelView?.connectionClosed(error: nil)
        }
        return true
    }

    /// Streams run through the stream table, which closes them; there are no stream channels.
    func closeAllStreams() -> [EventLoopFuture<Void>] {
        []
    }

    /// The consumer is told about the connection closing through its stream table.
    func quiesceStreams() {}

    /// Datagram flows are not driven yet.
    func writeDatagram(_ datagram: ByteBuffer) -> Bool {
        false
    }

    func flushDatagrams() {}

    func dropChannelReferences() {
        self.channelView = nil
        self.streamTable?.outOfBandDrain = nil
        if self.closedLocally && !self.isClosed {
            // The connection still closes or drains (RFC 9000 Section 10.2): keep its timer, which
            // holds the connection until it reports its disconnect.
        } else {
            self.timer?.cancel()
            self.timer = nil
            self.timerDeadline = nil
        }
        self.environment.scheduler.onWorkAvailable = nil
        self.workTarget?.connection = nil
        self.workTarget = nil
    }

    /// Whether the channel is gone but the connection still closes or drains, and wants the peer's
    /// packets until it is closed.
    var isClosingWithoutChannel: Bool {
        self.channelView == nil && self.closedLocally && !self.isClosed
    }

    /// Keeps driving a connection whose channel went away until it is closed.
    func continueClosing(transport: QUICHandler<Consumer>.ChildView, onClosed: @escaping () -> Void) {
        precondition(self.isClosingWithoutChannel)
        self.closingTransport = transport
        self.onClosedWithoutChannel = onClosed
    }

    /// Processes a datagram for a connection whose channel went away.
    func receiveWhileClosing(_ envelope: AddressedEnvelope<ByteBuffer>) {
        guard self.closingTransport != nil else { return }
        var datagram = envelope.data
        self.environment.scheduler.advance(to: Self.now)
        var frames = FrameArray(capacity: 1)
        Self.append(&datagram, to: &frames)
        self.quic.receiveFromBelow(path: self.quic.primaryPath, frames)
        self.afterUpdate()
    }

    /// Stops driving a connection whose channel went away: the handler is going away.
    func abandonClosing() {
        self.timer?.cancel()
        self.timer = nil
        self.timerDeadline = nil
        self.closingTransport = nil
        self.onClosedWithoutChannel = nil
    }

    // MARK: Streams

    /// Opens a stream for a slot.
    func openStream(for handle: QUICStreamHandle, bidirectional: Bool) {
        guard bidirectional else {
            // The standalone protocol opens bidirectional streams only.
            self.streamTable?.streamDisconnected(handle, error: NetworkError.posix(ENOTSUP))
            return
        }
        do throws(NetworkError) {
            let flowID = try self.quic.openStream()
            let flow = StandaloneStreamFlow(flowID: flowID)
            flow.handle = handle
            self.flows.insert(flow)
            self.streamTable?.attachFlow(flow, to: handle)
            self.quic.connect(flow: flowID)
            self.environment.turn()
            self.processEvents()
            self.outputProduced()
        } catch {
            self.streamTable?.streamDisconnected(handle, error: error)
        }
    }

    /// Forgets a locally opened stream that never got an ID.
    func cancelPendingOpen(flow: StandaloneStreamFlow?) {
        guard let flow else { return }
        self.release(flow)
    }

    /// Hands what the stream holds to `body`, which returns how many bytes it took. Whether `body`
    /// ran is returned.
    @discardableResult
    func read(
        _ flow: StandaloneStreamFlow,
        _ body: (RawSpan, _ isFinished: Bool) -> Int
    ) -> Bool {
        // The bytes wait in the stack's own receive queue for this visit, so they are read from what
        // the pull returns: the stream's queue here only holds what the consumer left behind.
        var frames: FrameArray
        let pulled: FrameArray? =
            flow.sawFin ? nil : (try? self.quic.receiveStreamData(flow: flow.flowID, minimumBytes: 1, maximumBytes: Int.max))
        if flow.pending.isEmpty {
            frames = pulled ?? FrameArray()
        } else {
            if let pulled { flow.pending.add(frames: pulled) }
            frames = flow.pending.drainArray()
        }

        // The consumer sees the bytes the stack holds as one contiguous run, as it would from a
        // receive buffer: merge frames when there are several.
        Self.coalesce(&frames)

        var ran = false
        frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
            let available = frame.unclaimedLength
            let isFinished = frame.connectionComplete
            if isFinished { flow.sawFin = true }
            let consumed: Int
            if let bytes = frame.bytes {
                consumed = body(bytes, isFinished)
            } else {
                consumed = body(RawSpan(), isFinished)
            }
            ran = true
            if consumed >= available {
                frame.finalize(success: true)
                return .removeFrameAndContinue
            }
            if consumed > 0 {
                _ = frame.claim(fromStart: consumed)
            }
            return .stopIterating
        }
        if !frames.isEmpty {
            // The consumer left bytes: keep them for its next read.
            flow.pending.add(frames: frames)
        }
        if !ran, flow.sawFin {
            // The FIN arrived on its own, and was consumed with an earlier read.
            _ = body(RawSpan(), true)
            ran = true
        }
        self.outputProduced()
        return ran
    }

    private static func coalesce(_ frames: inout FrameArray) {
        guard frames.count > 1 else { return }
        var total = 0
        var isFinal = false
        frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
            total += frame.unclaimedLength
            isFinal = isFinal || frame.connectionComplete
            return .continueIterating
        }
        var merged = Frame(count: total)
        var offset = 0
        frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
            let length = frame.unclaimedLength
            if length > 0, let source = frame.span, var target = merged.mutableSpan {
                source.withUnsafeBufferPointer { source in
                    target.withUnsafeMutableBufferPointer { target in
                        UnsafeMutableRawBufferPointer(rebasing: UnsafeMutableRawBufferPointer(target)[offset..<offset + length])
                            .copyMemory(from: UnsafeRawBufferPointer(source))
                    }
                }
                offset += length
            }
            frame.finalize(success: true)
            return .removeFrameAndContinue
        }
        if isFinal {
            merged.metadataComplete = true
            merged.connectionComplete = true
        }
        frames.add(frame: merged)
    }

    func writableBytes() -> Int {
        // The protocol queues whatever it is given and applies flow control itself.
        4 << 20
    }

    /// Hands frames to a stream, with the FIN on the last one if `fin`. Returns whether the
    /// protocol took them.
    @discardableResult
    func write(_ frames: consuming FrameArray, to flow: StandaloneStreamFlow, fin: Bool) -> Bool {
        var frames = frames
        if fin {
            if frames.isEmpty {
                frames.add(frame: Frame(count: 0))
            }
            var remaining = frames.count
            frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
                remaining -= 1
                if remaining == 0 {
                    frame.metadataComplete = true
                    frame.connectionComplete = true
                }
                return .continueIterating
            }
        }
        do throws(NetworkError) {
            try self.quic.sendStreamData(flow: flow.flowID, frames, early: false)
        } catch {
            return false
        }
        self.outputProduced()
        return true
    }

    func resetStream(_ flow: StandaloneStreamFlow, code: QUICApplicationErrorCode) {
        try? self.quic.abortOutbound(flow: flow.flowID, error: NetworkError(quicApplicationError: Int64(code.rawValue)))
        self.outputProduced()
    }

    func stopSending(_ flow: StandaloneStreamFlow, code: QUICApplicationErrorCode) {
        try? self.quic.abortInbound(flow: flow.flowID, error: NetworkError(quicApplicationError: Int64(code.rawValue)))
        self.outputProduced()
    }
}
