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

import Logging
import NIOCore
import X509

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

@available(anyAppleOS 26, *)
private enum MultiplexerContinuation<Consumer: QUICStreamConsumer & ~Copyable> {
    case connectionMultiplexerContinuation(
        any ConnectionMultiplexerContinuation<QUICConnectionChannel<Consumer>>
    )
    case closure(
        connectionInitializer: @Sendable (any Channel, QUICStreamCreator) -> EventLoopFuture<Void>,
        inboundStreamInitializer: @Sendable (any Channel) -> EventLoopFuture<Void>,
        finish: @Sendable () -> Void,
        role: Role
    )
}

/// A handler for QUIC connections.
///
/// Add this to a UDP channel to multiplex multiple QUIC connections.
///
/// QUIC must not let the IP layer fragment its datagrams (RFC 9000, § 14). You can use
/// ``QUICDontFragment/set(on:)`` to set the related socket options on the channel:
///
/// ```swift
/// let bootstrap = DatagramBootstrap(group: MultiThreadedEventLoopGroup.singleton)
/// let channel = try await bootstrap.bind(host: "127.0.0.1", port: 8443).get()
/// let keyPath = "/path/to/key"
/// let certPath = "/path/to/cert"
/// try await channel.eventLoop.submit {
///     let quicHandler = QUICHandler(
///         channel: channel,
///         quicConfiguration: .server(
///             serverName: "example.com",
///             authenticationConfiguration: .x509Certificates(
///                 certificateChainFilePath: certPath,
///                 privateKeyFilePath: keyPath
///             ),
///             applicationProtocols: ["http/0.9"]
///         ),
///         asyncVerifier: nil, // only used by clients: mTLS is currently not supported
///         authenticator: try .init(certificateFilePath: certPath, privateKeyFilePath: keyPath),
///         logger: Logger(label: "MyQUICServer"),
///         inboundConnectionInitializer: { channel, _ in
///             // Initialize the connection channel.
///             channel.eventLoop.makeSucceededVoidFuture()
///         },
///         inboundStreamInitializer: { channel in
///             // Initialize the stream channels.
///             channel.eventLoop.makeSucceededVoidFuture()
///         },
///         noMoreConnections: {}
///     )
///     // Set don't fragement before installing the QUIC handler.
///     try QUICDontFragment.set(on: channel)
///     try channel.pipeline.syncOperations.addHandler(quicHandler)
/// }.get()
/// ```
///
@available(anyAppleOS 26, *)
public final class QUICHandler<Consumer: QUICStreamConsumer & ~Copyable> {
    private enum State {
        case accepting
        case shuttingDown(EventLoopPromise<Void>)
        case shutdown(EventLoopFuture<Void>)
    }

    /// The channel this handler resides in.
    public let udpChannel: any Channel

    /// The QUIC configuration.
    private let quicConfiguration: QUICConfiguration

    /// A registry of connections.
    private var connectionRegistry: ConnectionRegistry<QUICConnectionChannel<Consumer>.TransportView>
    /// State machine connections whose channel closed while their connection still closes or drains
    /// (RFC 9000 Section 10.2), under the routes they had. They answer their peer's packets until
    /// the connection is closed.
    private var closingConnections: ConnectionRegistry<StateMachineQUICConnection<Consumer>>
    /// Decides whether new connections may be admitted.
    private var connectionAdmissionController: ConnectionAdmissionController

    /// How new connections are surfaced to the user: either a multiplexer continuation or a pair
    /// of initializer closures.
    private var multiplexerContinuation: MultiplexerContinuation<Consumer>?
    /// The event loop of the channel we are added to.
    private let eventLoop: any EventLoop
    /// The deadlines of the state machine connections on the loop, and the loop's clock for them.
    private let timerQueue: QUICTimerQueue
    /// The logger used everywhere.
    private let logger: Logger
    /// The generator used for creating source connection IDs for new connections.
    private var connectionIDGenerator: any QUICConnectionID.Generator
    /// The generator for stateless reset tokens (RFC 9000 § 10.3.2).
    ///
    /// Derives the stateless reset tokens for the connection IDs issued by this handler's
    /// connections, and for the resets this handler sends on their behalf once they are gone.
    private let statelessResetTokenGenerator: any QUICStatelessResetToken.Generator
    /// Our current state.
    private var state: State = .accepting
    /// Boolean to indicate if we wrote something.
    private var didWrite = false
    /// Whether we're expecting a channelReadComplete. This is used to delay flushing the channel until the a read complete is received.
    private var expectingChannelReadComplete: Bool = false
    /// Connections which read at least one datagram in the read loop.
    private var connectionsAwaitingReadComplete: [QUICConnectionChannel<Consumer>.TransportView] = []
    /// The context of the channel handler.
    private var context: ChannelHandlerContext?
    /// The next connection handle to use. Don't use directly, use `nextConnectionHandle()` instead.
    private var connectionHandle: ConnectionHandle
    /// Verifies the server identitfy.
    private var asyncVerifierRunner: AsyncVerifierRunner?
    /// Provide certificates and signature to authenticate.
    private var authenticator: Authenticator?
    /// Makes a consumer for a given connection, `nil` if stream channels are used.
    private let makeConsumer: ((QUICStreamConnection<Consumer>) -> Consumer)?
    /// The implementation that drives new consumer connections. Set it before the first
    /// connection is created.
    var connectionDriver: QUICConnectionDriver

    private func nextConnectionHandle() -> ConnectionHandle {
        let handle = self.connectionHandle
        self.connectionHandle.formNext()
        return handle
    }

    /// Initialises a new QUIC handler.
    ///
    /// - Parameters:
    ///   - channel: The channel this handler resides in.
    ///   - quicConfiguration: The quic configuration to use for this handler.
    ///   - connectionLimits: Limits on the inbound connections this handler admits.
    ///   - asyncVerifier: Callback provider for SwiftTLS certificate verification.
    ///   - logger: The logger.
    ///   - makeConsumer: Builds the consumer servicing a connection's streams, or nil
    ///     when streams are surfaced as child channels.
    ///   - connectionIDGenerator: The generator used for creating source connection IDs.
    ///   - statelessResetTokenGenerator: The generator used to derive stateless reset tokens for each connection ID.
    init(
        channel: any Channel,
        quicConfiguration: QUICConfiguration,
        connectionLimits: QUICConnectionLimits,
        asyncVerifier: AsyncVerifier?,
        authenticator: Authenticator?,
        logger: Logger,
        makeConsumer: ((_ connection: QUICStreamConnection<Consumer>) -> Consumer)?,
        connectionIDGenerator: any QUICConnectionID.Generator = QUICConnectionID.RandomGenerator(),
        statelessResetTokenGenerator: any QUICStatelessResetToken.Generator = .defaultWithAutoGeneratedKey,
    ) {
        self.udpChannel = channel
        self.eventLoop = channel.eventLoop
        self.timerQueue = QUICTimerQueue(eventLoop: channel.eventLoop)
        self.quicConfiguration = quicConfiguration
        self.logger = logger
        self.connectionIDGenerator = connectionIDGenerator
        self.statelessResetTokenGenerator = statelessResetTokenGenerator
        if let asyncVerifier {
            self.asyncVerifierRunner = .init(asyncVerifier: asyncVerifier)
        }
        self.authenticator = authenticator
        self.connectionHandle = .initial
        self.connectionRegistry = ConnectionRegistry()
        self.closingConnections = ConnectionRegistry()
        self.makeConsumer = makeConsumer
        self.connectionDriver = .default(for: quicConfiguration.role)
        self.connectionAdmissionController = makeConnectionAdmissionController(
            for: connectionLimits,
            logger: logger,
            eventLoop: channel.eventLoop
        )
    }

    /// Shuts the server down gracefully.
    ///
    /// - Parameters:
    ///     - deadline: Deadline until connections are closed gracefully. Afterwards they will be forcibly closed.
    /// - Returns: A future that is notified once the server is closed.
    public func shutdownGracefully(deadline: NIODeadline) -> EventLoopFuture<Void> {
        let promise = self.eventLoop.makePromise(of: Void.self)
        self.shutdownGracefully(deadline: deadline, promise: promise)
        return promise.futureResult
    }

    private func shutdownGracefully(deadline: NIODeadline, promise: EventLoopPromise<Void>) {
        self.eventLoop.assertInEventLoop()

        switch self.state {
        case .shutdown(let shutdownFuture):
            self.logger.trace("QUICHandler is already shutdown")
            shutdownFuture.cascade(to: promise)
        case .shuttingDown(let shutdownPromise):
            self.logger.trace("QUICHandler is already trying to shutdown gracefully")
            shutdownPromise.futureResult.cascade(to: promise)
        case .accepting:
            self.logger.trace("QUICHandler is trying to shut down gracefully")
            let internalPromise = self.eventLoop.makePromise(of: Void.self).assumeIsolated()
            internalPromise.futureResult.nonisolated().cascade(to: promise)
            self.state = .shuttingDown(internalPromise.nonisolated())

            internalPromise.futureResult.whenComplete { result in
                self.didShutDown(result)
            }

            self.connectionRegistry.shutdownConnections(
                deadline: deadline,
                promise: internalPromise
            )
        }
    }

    private func didShutDown(_ result: Result<Void, any Error>) {
        self.eventLoop.assertInEventLoop()
        switch self.state {
        case .accepting, .shutdown:
            preconditionFailure("We should be shutting down right now.")
        case .shuttingDown(let promise):
            self.logger.trace("QUICHandler shutdown")
            self.state = .shutdown(promise.futureResult)
            promise.completeWith(result)
        }
    }

    private func createNewConnection(
        promise: EventLoopPromise<(QUICConnectionChannel<Consumer>, QUICStreamCreator)>,
        serverName: String,
        remoteAddress: SocketAddress,
        connectionInitializer:
            @Sendable @escaping (
                _ channel: QUICConnectionChannel<Consumer>,
                _ streamCreator: QUICStreamCreator
            ) -> EventLoopFuture<Void>
    ) throws {
        switch self.state {
        case .accepting:
            guard let localAddress = self.context?.localAddress else {
                return promise.fail(QUICError.noLocalAddress)
            }
            let sourceConnectionID = self.connectionIDGenerator.next()

            let connectionLogger = {
                var logger = logger
                logger[metadataKey: LoggingKeys.connectionOriginalSCID] = "\("none")"
                logger[metadataKey: LoggingKeys.connectionSCID] = "\(sourceConnectionID)"
                logger[metadataKey: LoggingKeys.connectionDCID] = "\("none")"
                logger[metadataKey: LoggingKeys.addressLocal] = "\(localAddress)"
                logger[metadataKey: LoggingKeys.addressRemote] = "\(remoteAddress)"
                return logger
            }()
            let handle = self.nextConnectionHandle()
            let channel: QUICConnectionChannel<Consumer>
            var stateMachineConnection: StateMachineQUICConnection<Consumer>?
            if self.makeConsumer != nil && self.connectionDriver == .stateMachine
                && QUICConnectionDriver.stateMachineSupports(self.quicConfiguration)
            {
                let connection = try StateMachineQUICConnection<Consumer>.client(
                    configuration: self.quicConfiguration,
                    sourceConnectionID: sourceConnectionID,
                    serverName: serverName,
                    asyncVerifier: asyncVerifierRunner?.asyncVerifier,
                    localAddress: localAddress,
                    remoteAddress: remoteAddress,
                    eventLoop: self.context!.eventLoop,
                    timers: self.timerQueue,
                    logger: connectionLogger
                )
                channel = self.makeQUICConnectionChannel(stateMachineConnection: connection, handle: handle)
                stateMachineConnection = connection
            } else {
                // The context is set when the channel becomes active so force unwrapping is okay here
                let quicConnection = try SwiftNetworkQUICConnection<Consumer>.client(
                    configuration: self.quicConfiguration,
                    sourceConnectionID: sourceConnectionID,
                    statelessResetTokenGenerator: self.statelessResetTokenGenerator,
                    serverName: serverName,
                    asyncVerifier: asyncVerifierRunner?.asyncVerifier,
                    localAddress: localAddress,
                    remoteAddress: remoteAddress,
                    eventLoop: self.context!.eventLoop,
                    logger: connectionLogger,
                    usesStreamTable: self.makeConsumer != nil
                )
                channel = self.makeQUICConnectionChannel(
                    quicConnection: quicConnection,
                    handle: handle
                )
            }
            let view = channel.transportView
            self.connectionRegistry.insert(view, forHandle: handle, connectionID: sourceConnectionID)

            let streamCreator = channel.makeStreamCreator(role: self.quicConfiguration.role)
            let activePromise = self.eventLoop.makePromise(of: Void.self)

            view.initialize(readyPromise: activePromise, handshakePromise: nil) { channel in
                connectionInitializer(channel, streamCreator)
            }

            activePromise.futureResult
                .assumeIsolated()
                .whenComplete { result in
                    switch result {
                    case .success:
                        promise.succeed((channel, streamCreator))
                    case .failure(let error):
                        promise.fail(error)
                    }
                }

            channel.closeFuture.assumeIsolated().whenComplete { _ in
                self.connectionDidClose(handle, stateMachineConnection: stateMachineConnection)
            }

        case .shuttingDown:
            promise.fail(QUICError.quicHandlerShuttingDown)

        case .shutdown:
            promise.fail(QUICError.quicHandlerShutdown)
        }
    }

    /// Hands the packet which created a connection to its channel once the connection has been
    /// initialized.
    ///
    /// The connection only queues the packet: it consumes its queue when the parent channel's read
    /// loop ends. If the connection initializer completed asynchronously then that read loop has
    /// already ended and no 'channelReadComplete' is coming for this packet, so the end of the read
    /// loop is signalled here instead. Without it the packet — an INITIAL, so the whole handshake —
    /// waits for the peer to retransmit.
    private func deliverFirstPacket(
        _ envelope: AddressedEnvelope<ByteBuffer>,
        to view: QUICConnectionChannel<Consumer>.TransportView
    ) {
        self.eventLoop.assertInEventLoop()
        self.deliverPacket(envelope, to: view)

        // First reads can be delivered outside of the read loop (i.e. after the connection init)
        // so notify read complete out-of-band if necessary.
        if !self.expectingChannelReadComplete {
            self.notifyPendingReadCompletions()
        }
    }

    private func deliverPacket(
        _ envelope: AddressedEnvelope<ByteBuffer>,
        to view: QUICConnectionChannel<Consumer>.TransportView
    ) {
        let didEnterReadLoop = view.parentChannelRead(envelope)

        if didEnterReadLoop {
            self.connectionsAwaitingReadComplete.append(view)
        }
    }

    private func notifyPendingReadCompletions() {
        for view in self.connectionsAwaitingReadComplete {
            view.parentChannelReadComplete()
        }

        self.connectionsAwaitingReadComplete.removeAll(keepingCapacity: true)
    }

    private func connectionDidClose(
        _ handle: ConnectionHandle,
        stateMachineConnection: StateMachineQUICConnection<Consumer>?
    ) {
        self.eventLoop.assertInEventLoop()
        let connectionIDs = self.connectionRegistry.connectionIDs(for: handle)
        self.connectionRegistry.remove(handle)

        // A state machine connection outlives its channel while it closes or drains
        // (RFC 9000 Section 10.2): keep routing the peer's packets to it, so that it answers them
        // with CONNECTION_CLOSE, until the connection is closed. Not once the UDP channel is gone.
        guard let connection = stateMachineConnection, connection.isClosingWithoutChannel,
            let firstConnectionID = connectionIDs.first, self.context?.channel.isActive == true
        else { return }
        self.closingConnections.insert(connection, forHandle: handle, connectionID: firstConnectionID)
        for connectionID in connectionIDs.dropFirst() {
            self.closingConnections.associate(connectionID, with: handle)
        }
        // The cycle through the handler is broken when the connection is closed, or in
        // `abandonClosingConnections()`.
        connection.continueClosing(transport: ChildView(self)) {
            self.closingConnections.remove(handle)
        }
    }

    /// Stops driving the connections that close without a channel: the UDP channel is gone.
    private func abandonClosingConnections() {
        for connection in self.closingConnections.values {
            connection.abandonClosing()
        }
        self.closingConnections = ConnectionRegistry()
    }

    /// Hands a short-header packet that routes to no connection to the connections with its sender.
    ///
    /// A stateless reset carries no connection ID of ours: only a connection can recognize it, by
    /// the token it ends in (RFC 9000 Section 10.3.1). A client has few connections, so it hands
    /// such a packet to each one with the sender as its peer.
    ///
    /// - Returns: Whether a connection got the packet.
    private func deliverPossibleStatelessReset(_ envelope: AddressedEnvelope<ByteBuffer>) -> Bool {
        // The shortest stateless reset: a header byte, four unpredictable bytes and the token
        // (RFC 9000 Section 10.3).
        guard envelope.data.readableBytes >= 21 else { return false }

        var delivered = false
        for view in self.connectionRegistry.values where view.remoteAddress == envelope.remoteAddress {
            self.deliverPacket(envelope, to: view)
            delivered = true
        }
        return delivered
    }

    /// Answers a packet which routes to no connection with a stateless reset (RFC 9000 § 10.3),
    /// telling the peer to give up on a connection this endpoint has no state for.
    ///
    /// Requirements to send a stateless reset:
    /// * The incoming packet must be a short-header packet.
    /// * The incoming packet must be longer than 21 bytes.
    /// * The related connection ID must be longer than 0 bytes.
    ///
    /// - Parameters:
    ///   - header: The parsed header of the unroutable packet.
    ///   - envelope: The datagram it arrived in.
    private func trySendStatelessReset(
        for header: QUICPacketHeader,
        triggeredBy envelope: AddressedEnvelope<ByteBuffer>
    ) {
        self.eventLoop.assertInEventLoop()

        // RFC 9000 § 10.3 says that we may send stateless reset in response to long headers.
        // However, long header packets are only used before the handshake completes,
        // at which point the peer doesn't have a token to compare the reset against yet,
        // so answering it can be ommited in current versions.
        guard header.type == .short else {
            return
        }
        // Token can only be derived for non-zero length connection IDs.
        guard self.connectionIDGenerator.connectionIDLength > 0 else { return }

        let reset = self.statelessResetTokenGenerator.statelessResetPacket(
            for: header.destinationConnectionID,
            triggeringPacketLength: envelope.data.readableBytes,
            allocator: self.udpChannel.allocator
        )

        // Packet generation will fail if no valid packet can be created as a response
        // (e.g., the packet is too small).
        guard let reset else { return }

        self.logger.debug(
            "QUICHandler sending stateless reset",
            metadata: [
                LoggingKeys.addressRemote: "\(envelope.remoteAddress)",
                LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                LoggingKeys.channelOutboundBytes: "\(reset.readableBytes)",
            ]
        )

        self.writeDatagram(
            AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: reset),
            promise: nil
        )
    }

    /// Answers a long header packet in a version this endpoint doesn't support with a Version
    /// Negotiation packet (RFC 9000 Section 6.1).
    private func trySendVersionNegotiation(
        for header: QUICPacketHeader,
        triggeredBy envelope: AddressedEnvelope<ByteBuffer>
    ) {
        self.eventLoop.assertInEventLoop()

        // RFC 9000 Section 6.1: "An endpoint MUST NOT send a Version Negotiation packet in
        // response to receiving a Version Negotiation packet."
        guard header.version != .negotiation else {
            return
        }
        // RFC 9000 Section 5.2.2: a server answers a packet only "if the packet is large enough
        // to initiate a new connection for any supported version", and "Servers MUST drop smaller
        // packets that specify unsupported versions". A version 1 Initial fills a datagram of at
        // least 1200 bytes (RFC 9000 Section 14.1). This also keeps the answer smaller than the
        // packet, so it doesn't amplify.
        guard envelope.data.readableBytes >= 1200 else {
            return
        }
        guard let versionNegotiation = header.versionNegotiationPacket(allocator: self.udpChannel.allocator) else {
            return
        }

        self.logger.debug(
            "QUICHandler sending version negotiation",
            metadata: [
                LoggingKeys.addressRemote: "\(envelope.remoteAddress)",
                LoggingKeys.packetVersion: "\(String(describing: header.version))",
                LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                LoggingKeys.channelOutboundBytes: "\(versionNegotiation.readableBytes)",
            ]
        )

        self.writeDatagram(
            AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: versionNegotiation),
            promise: nil
        )
    }
}

@available(*, unavailable)
extension QUICHandler: Sendable where Consumer: ~Copyable {}

/// The `Channel` based stream API.
///
/// Streams are surfaced as child channels rather than to a ``QUICStreamConsumer``, so these
/// entry points are only available when the handler's consumer is ``QUICStreamChannels``.
@available(anyAppleOS 26, *)
extension QUICHandler where Consumer == QUICStreamChannels {
    /// Creates a new ``QUICHandler`` and a ``QUICHandler/ConnectionMultiplexer``.
    ///
    /// - Parameters:
    ///   - channel: The channel this handler resides in.
    ///   - QUICConfiguration: The quic configuration to use for this handler.
    ///   - connectionLimits: Limits on the inbound connections this handler admits. Only used by servers.
    ///     Defaults to ``QUICConnectionLimits/perHandler(activeLimit:handshakeLimit:newConnectionRateLimit:)``
    ///     with 10,000 active connections and a rate limit of 1,000 new connections per second.
    ///   - logger: The logger.
    ///   - inboundStreamChannelInitializer: A closure called for any new inbound stream.
    /// - Returns: The handler and the connection multiplexer.
    public static func makeHandlerAndConnectionMultiplexer<Output: Sendable>(
        channel: any Channel,
        quicConfiguration: QUICConfiguration,
        connectionLimits: QUICConnectionLimits = .perHandler(),
        logger: Logger,
        inboundStreamChannelInitializer: @Sendable @escaping (any Channel) -> EventLoopFuture<Output>
    ) throws -> (QUICHandler, QUICHandler.ConnectionMultiplexer<Output>) {
        try self.makeHandlerAndConnectionMultiplexer(
            channel: channel,
            quicConfiguration: quicConfiguration,
            connectionLimits: connectionLimits,
            logger: logger,
            inboundStreamChannelInitializer: inboundStreamChannelInitializer,
            connectionIDGenerator: QUICConnectionID.RandomGenerator(),
            statelessResetTokenGenerator: .defaultWithAutoGeneratedKey
        )
    }

    /// Creates a new ``QUICHandler`` and a ``QUICHandler/ConnectionMultiplexer``.
    ///
    /// To generate consistent QUIC stateless reset token across restarts, configure the
    /// `statelessResetTokenGenerator` with a persistent key using `.defaultWithUserProvidedKey(:)`
    /// or a custom implementation that keeps a persistent key. The default auto generates a new key
    /// on initialization, which results in different tokens after a restart.
    ///
    /// - Parameters:
    ///   - channel: The channel this handler resides in.
    ///   - QUICConfiguration: The quic configuration to use for this handler.
    ///   - connectionLimits: Limits on the inbound connections this handler admits. Only used by servers.
    ///     Defaults to ``QUICConnectionLimits/perHandler(activeLimit:handshakeLimit:newConnectionRateLimit:)``
    ///     with 10,000 active connections and a rate limit of 1,000 new connections per second.
    ///   - logger: The logger.
    ///   - inboundStreamChannelInitializer: A closure called for any new inbound stream.
    ///   - connectionIDGenerator: The generator used for creating source connection IDs.
    ///   - statelessResetTokenGenerator: The generator used to derive stateless reset tokens for each connection ID.
    /// - Returns: The handler and the connection multiplexer.
    public static func makeHandlerAndConnectionMultiplexer<Output: Sendable>(
        channel: any Channel,
        quicConfiguration: QUICConfiguration,
        connectionLimits: QUICConnectionLimits = .perHandler(),
        logger: Logger,
        inboundStreamChannelInitializer: @Sendable @escaping (any Channel) -> EventLoopFuture<Output>,
        connectionIDGenerator: any QUICConnectionID.Generator,
        statelessResetTokenGenerator: any QUICStatelessResetToken.Generator = .defaultWithAutoGeneratedKey
    ) throws -> (QUICHandler, QUICHandler.ConnectionMultiplexer<Output>) {

        // If this is a client using certificates (the raw public key configuration paths are not set), we need to
        // create a verifier for the TLS handshake. At the moment there is no mTLS support, so only
        // clients need to do this.
        //
        // See also: https://github.com/apple/swift-nio-quic/issues/5
        let asyncVerifier: AsyncVerifier?
        if quicConfiguration.role == .client,
            let verifierConfiguration = quicConfiguration.verificationConfiguration,
            case .x509Certificates(trustRootsFilePath: let trustRootsPath) = verifierConfiguration
        {
            if let trustRootsPath {
                asyncVerifier = try AsyncVerifier(
                    trustRootsPath: trustRootsPath,
                    certificateVerification: quicConfiguration.peerCertificateVerification,
                    eventLoop: channel.eventLoop
                )
            } else {
                asyncVerifier = AsyncVerifier(
                    certificateVerification: quicConfiguration.peerCertificateVerification,
                    eventLoop: channel.eventLoop
                )
            }
        } else {
            asyncVerifier = nil
        }

        let authenticator: Authenticator?
        if quicConfiguration.role == .server,
            let authenticatorConfiguration = quicConfiguration.authenticationConfiguration,
            case .x509Certificates(
                certificateChainFilePath: let certificateChainFilePath,
                privateKeyFilePath: let privateKeyFilePath
            ) = authenticatorConfiguration
        {
            authenticator = try Authenticator(
                certificateFilePath: certificateChainFilePath,
                privateKeyFilePath: privateKeyFilePath
            )
        } else {
            authenticator = nil
        }

        let handler = QUICHandler(
            channel: channel,
            quicConfiguration: quicConfiguration,
            connectionLimits: connectionLimits,
            asyncVerifier: asyncVerifier,
            authenticator: authenticator,
            logger: logger,
            makeConsumer: nil,
            connectionIDGenerator: connectionIDGenerator,
            statelessResetTokenGenerator: statelessResetTokenGenerator
        )

        let multiplexer = ConnectionMultiplexer(
            eventLoop: channel.eventLoop,
            role: quicConfiguration.role,
            inboundStreamInitializer: inboundStreamChannelInitializer,
            createNewConnection: NIOLoopBound(handler.createNewConnection, eventLoop: channel.eventLoop)
        )

        handler.multiplexerContinuation = .connectionMultiplexerContinuation(multiplexer)

        return (handler, multiplexer)
    }

    /// Initialises a new ``QUICHandler``.
    ///
    /// To generate consistent QUIC stateless reset token across restarts, configure the
    /// `statelessResetTokenGenerator` with a persistent key using `.defaultWithUserProvidedKey(:)`
    /// or a custom implementation that keeps a persistent key. The default auto generates a new key
    /// on initialization, which results in different tokens after a restart.
    ///
    /// - Parameters:
    ///   - channel: The channel this handler resides in.
    ///   - quicConfiguration: The quic configuration to use for this handler.
    ///   - connectionLimits: Limits on the inbound connections this handler admits. Only used by servers.
    ///     Defaults to ``QUICConnectionLimits/perHandler(activeLimit:handshakeLimit:newConnectionRateLimit:)``
    ///     with 10,000 active connections and a rate limit of 1,000 new connections per second.
    ///   - asyncVerifier: Callback provider for SwiftTLS certificate verification.
    ///   - authenticator: Authenticator for SwiftTLS certificate verification.
    ///   - logger: The logger.
    ///   - inboundConnectionInitializer: Called for every incoming connection and allows you to add handlers.
    ///   - inboundStreamInitializer: Called for every incoming stream on inbound connections and allows you to add handlers. This isn't called for inbound streams on outbound connections.
    ///   - noMoreConnections: Called when this handler becomes inactive. After this, `inboundConnectionInitializer` won't be called again.
    ///   - connectionIDGenerator: The generator used for creating source connection IDs.
    ///   - statelessResetTokenGenerator: The generator used to derive stateless reset tokens for each connection ID.
    public convenience init(
        channel: any Channel,
        quicConfiguration: QUICConfiguration,
        connectionLimits: QUICConnectionLimits = .perHandler(),
        asyncVerifier: AsyncVerifier?,
        authenticator: Authenticator?,
        logger: Logger,
        inboundConnectionInitializer: @escaping @Sendable (any Channel, QUICStreamCreator) -> EventLoopFuture<Void>,
        inboundStreamInitializer: @escaping @Sendable (any Channel) -> EventLoopFuture<Void>,
        noMoreConnections: @escaping @Sendable () -> Void,
        connectionIDGenerator: any QUICConnectionID.Generator = QUICConnectionID.RandomGenerator(),
        statelessResetTokenGenerator: any QUICStatelessResetToken.Generator = .defaultWithAutoGeneratedKey
    ) {
        self.init(
            channel: channel,
            quicConfiguration: quicConfiguration,
            connectionLimits: connectionLimits,
            asyncVerifier: asyncVerifier,
            authenticator: authenticator,
            logger: logger,
            makeConsumer: nil,
            connectionIDGenerator: connectionIDGenerator,
            statelessResetTokenGenerator: statelessResetTokenGenerator
        )

        self.multiplexerContinuation = .closure(
            connectionInitializer: inboundConnectionInitializer,
            inboundStreamInitializer: inboundStreamInitializer,
            finish: noMoreConnections,
            role: quicConfiguration.role
        )
    }

    /// Create a new outbound QUIC connection.
    /// - Parameters:
    ///   - serverName: The server to connect to.
    ///   - remoteAddress: The address to connect to.
    ///   - connectionInitializer: How to initialize the connection. This closure will be called with a channel and a stream creator.
    ///   - inboundStreamInitializer: How to initialize any inbound streams on the new connection. This closure is
    ///     called with each new inbound stream channel; it is the only place inbound streams are surfaced. Add your per-stream handlers here.
    /// - Returns: The initialized connection channel and a stream creator to open outbound streams
    ///     on it with.
    public func createOutboundConnection(
        serverName: String,
        remoteAddress: SocketAddress,
        connectionInitializer: @escaping @Sendable (any Channel, QUICStreamCreator) -> EventLoopFuture<Void>,
        inboundStreamInitializer: @escaping @Sendable (any Channel) -> EventLoopFuture<Void>
    ) -> EventLoopFuture<(any Channel, QUICStreamCreator)> {
        let promise = self.eventLoop.makePromise(
            of: (QUICConnectionChannel<Consumer>, QUICStreamCreator).self
        )

        do {
            try self.createNewConnection(
                promise: promise,
                serverName: serverName,
                remoteAddress: remoteAddress
            ) { channel, streamCreator in
                channel.setInboundStreamInitializer(.closure(inboundStreamInitializer))
                return connectionInitializer(channel, streamCreator)
            }
        } catch {
            promise.fail(error)
        }

        return promise.futureResult.map { channel, streamCreator in (channel, streamCreator) }
    }
}

/// The ``QUICStreamConsumer`` based stream API.
@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    /// Initialises a new ``QUICHandler`` whose streams are serviced by a consumer.
    ///
    /// - Parameters:
    ///   - channel: The channel this handler resides in.
    ///   - quicConfiguration: The quic configuration to use for this handler.
    ///   - connectionLimits: Limits on the inbound connections this handler admits. Only used by servers.
    ///     Defaults to ``QUICConnectionLimits/perHandler(activeLimit:handshakeLimit:newConnectionRateLimit:)``
    ///     with 10,000 active connections and a rate limit of 1,000 new connections per second.
    ///   - asyncVerifier: Callback provider for SwiftTLS certificate verification.
    ///   - authenticator: Authenticator for SwiftTLS certificate verification.
    ///   - logger: The logger.
    ///   - connectionIDGenerator: The generator used for creating source connection IDs.
    ///   - statelessResetTokenGenerator: The generator used to derive stateless reset tokens for each connection ID.
    ///   - makeConsumer: Builds the consumer servicing a connection's streams. Called on the
    ///       connection's event loop once per connection.
    public convenience init(
        channel: any Channel,
        quicConfiguration: QUICConfiguration,
        connectionLimits: QUICConnectionLimits = .perHandler(),
        asyncVerifier: AsyncVerifier?,
        authenticator: Authenticator?,
        logger: Logger,
        connectionIDGenerator: any QUICConnectionID.Generator = QUICConnectionID.RandomGenerator(),
        statelessResetTokenGenerator: any QUICStatelessResetToken.Generator = .defaultWithAutoGeneratedKey,
        makeConsumer: @escaping (_ connection: QUICStreamConnection<Consumer>) -> Consumer
    ) {
        self.init(
            channel: channel,
            quicConfiguration: quicConfiguration,
            connectionLimits: connectionLimits,
            asyncVerifier: asyncVerifier,
            authenticator: authenticator,
            logger: logger,
            makeConsumer: makeConsumer,
            connectionIDGenerator: connectionIDGenerator,
            statelessResetTokenGenerator: statelessResetTokenGenerator
        )
    }

    /// Create a new outbound QUIC connection whose streams are serviced by a consumer.
    ///
    /// Streams on the connection, inbound and outbound alike, are surfaced to the consumer
    /// the handler's `makeConsumer` closure builds for it; there is no per-stream channel
    /// and no stream creator.
    ///
    /// - Parameters:
    ///   - serverName: The server to connect to.
    ///   - remoteAddress: The address to connect to.
    /// - Returns: The initialized connection, or a future which fails with
    ///   ``QUICError/noStreamConsumer`` if the handler services its streams with `Channel`s
    ///   instead of a consumer.
    public func createOutboundConnection(
        serverName: String,
        remoteAddress: SocketAddress
    ) -> EventLoopFuture<QUICStreamConnection<Consumer>> {
        // No consumer means no stream table (for now.) We'll need to think about this API a bit
        // more if/when we back stream channels with the table.
        if self.makeConsumer == nil {
            return self.eventLoop.makeFailedFuture(QUICError.noStreamConsumer)
        }

        let promise = self.eventLoop.makePromise(
            of: (QUICConnectionChannel<Consumer>, QUICStreamCreator).self
        )

        do {
            try self.createNewConnection(
                promise: promise,
                serverName: serverName,
                remoteAddress: remoteAddress
            ) { channel, _ in
                channel.eventLoop.makeSucceededVoidFuture()
            }
        } catch {
            promise.fail(error)
        }

        return promise.futureResult.map { channel, _ in QUICStreamConnection(channel: channel) }
    }
}

@available(anyAppleOS 26, *)
extension QUICHandler: ChannelInboundHandler where Consumer: ~Copyable {
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    public func handlerAdded(context: ChannelHandlerContext) {
        self.logger.trace("QUICHandler added to channel pipeline")
        self.context = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.logger.trace("QUICHandler removed from channel pipeline")
        self.context = nil
        self.connectionRegistry.shutdownConnections(deadline: .now(), promise: nil)
        self.abandonClosingConnections()
        self.timerQueue.cancelAll()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        self.logger.trace("QUICHandlers' parent channel became inactive")
        asyncVerifierRunner?.terminate()

        self.connectionRegistry.notifyParentChannelInactive()
        self.abandonClosingConnections()

        switch self.multiplexerContinuation {
        case .none:
            break
        case .closure(_, _, let onFinish, _):
            onFinish()
        case .connectionMultiplexerContinuation(let cont):
            cont.finish()
        }

        if let asyncVerifierRunner = self.asyncVerifierRunner {
            context.eventLoop.makeFutureWithTask {
                await asyncVerifierRunner.join()
            }.assumeIsolated().whenComplete { _ in
                context.fireChannelInactive()
            }
        } else {
            context.fireChannelInactive()
        }
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        self.logger.trace(
            "QUICHandlers' parent channel writability changed",
            metadata: [
                LoggingKeys.channelWritability: "\(context.channel.isWritable)"
            ]
        )

        let isWritable = context.channel.isWritable
        self.connectionRegistry.notifyParentChannelWritabilityChanged(isWritable)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.expectingChannelReadComplete = true
        let addressedEnvelope = self.unwrapInboundIn(data)

        let header = addressedEnvelope.data.parseQUICPacketHeader(
            destinationIDLength: self.connectionIDGenerator.connectionIDLength
        )

        guard let header else {
            self.logger.trace(
                "QUICHandler failed to parse packet",
                metadata: [
                    LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                    LoggingKeys.role: "\(self.quicConfiguration.role)",
                    "bytes": "\(addressedEnvelope.data.readableBytes)",
                ]
            )
            return
        }

        self.logger.trace(
            "QUICHandler received QUIC packet",
            metadata: [
                LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                LoggingKeys.packetType: "\(header.type)",
                LoggingKeys.packetVersion: "\(String(describing: header.version))",
                LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                LoggingKeys.role: "\(self.quicConfiguration.role)",
            ]
        )

        do {
            switch self.state {
            case .accepting:
                if let view = self.connectionRegistry[header.destinationConnectionID] {
                    self.deliverPacket(addressedEnvelope, to: view)
                } else if let connection = self.closingConnections[header.destinationConnectionID] {
                    connection.receiveWhileClosing(addressedEnvelope)
                } else if self.quicConfiguration.role == .server {
                    if header.type != .short, header.version != .v1 {
                        // A long header in a version we don't speak starts no connection. Version
                        // Negotiation is stateless, so the handler answers it for every driver
                        // (RFC 9000 Section 5.2.2).
                        self.trySendVersionNegotiation(for: header, triggeredBy: addressedEnvelope)
                    } else if header.type == .initial {
                        // Only INITIAL packets can create new connections.
                        switch self.connectionAdmissionController.acceptNewConnection() {
                        case .accept:
                            try self.acceptNewConnection(
                                for: addressedEnvelope,
                                sourceConnectionID: header.sourceConnectionID,
                                destinationConnectionID: header.destinationConnectionID,
                                // This force unwrap is fine. We really need to have a local address at this point
                                localAddress: context.localAddress!
                            )
                        case .drop(let reason):
                            self.logger.trace(
                                "QUICHandler dropping new connection",
                                metadata: [
                                    LoggingKeys.connectionDropReason: "\(reason)",
                                    LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                                    LoggingKeys.connectionDCID:
                                        "\(header.destinationConnectionID.description)",
                                ]
                            )
                        }
                    } else {
                        self.logger.trace(
                            "QUICHandler dropping non-INITIAL packet without a connection",
                            metadata: {
                                [
                                    LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                                    LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                                    LoggingKeys.connectionDCID:
                                        "\(header.destinationConnectionID.description)",
                                    LoggingKeys.packetType: "\(header.type)",
                                ]
                            }()
                        )
                        self.trySendStatelessReset(for: header, triggeredBy: addressedEnvelope)
                    }
                } else if header.type == .short, self.deliverPossibleStatelessReset(addressedEnvelope) {
                    // A client connection to the sender may recognize it as a stateless reset.
                    ()
                } else {
                    self.logger.warning(
                        "QUICHandler dropping packet",
                        metadata: [
                            LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                            LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                            LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                        ]
                    )
                    self.trySendStatelessReset(for: header, triggeredBy: addressedEnvelope)
                }
            case .shuttingDown:
                // We still need to forward packets to open connections but not accept new ones.
                if let connection = self.closingConnections[header.destinationConnectionID] {
                    connection.receiveWhileClosing(addressedEnvelope)
                    break
                }
                guard let view = self.connectionRegistry[header.destinationConnectionID] else {
                    self.logger.warning(
                        "QUICHandler dropping packet since the server is shutting down and not accepting new connections",
                        metadata: [
                            LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                            LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                            LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                        ]
                    )
                    self.trySendStatelessReset(for: header, triggeredBy: addressedEnvelope)
                    break
                }

                self.logger.trace(
                    "QUICHandler forwarding read to multiplexer",
                    metadata: [
                        LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                        LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                        LoggingKeys.connectionDCID: "\(header.destinationConnectionID)",
                    ]
                )

                self.deliverPacket(addressedEnvelope, to: view)

            case .shutdown:
                self.logger.warning(
                    "QUICHandler dropping packet since the server is shutdown",
                    metadata: [
                        LoggingKeys.addressRemote: "\(addressedEnvelope.remoteAddress)",
                        LoggingKeys.connectionSCID: "\(header.sourceConnectionID?.description ?? "none")",
                        LoggingKeys.connectionDCID: "\(header.destinationConnectionID.description)",
                    ]
                )
            }
        } catch {
            // We may also fire an error here even if we are already shutdown.
            context.fireErrorCaught(error)
            return
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        self.logger.trace("QUICHandler read complete")

        // The connections that read in this loop see the time it ended, and take the clock once.
        self.timerQueue.beginBatch()
        self.notifyPendingReadCompletions()
        self.timerQueue.endBatch()
        self.expectingChannelReadComplete = false

        if self.didWrite {
            self.didWrite = false
            self.logger.trace("QUICHandler flushing")
            context.flush()
        }
        context.fireChannelReadComplete()
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelShouldQuiesceEvent:
            let promise = context.eventLoop.makePromise(of: Void.self).assumeIsolated()
            promise.futureResult.whenComplete { _ in
                context.close(promise: nil)
            }

            self.connectionRegistry.shutdownConnections(
                deadline: .now() + .minutes(1),
                promise: promise
            )

        default:
            self.connectionRegistry.notifyParentChannelUserInboundEventTriggered(event)
        }
    }

    private func acceptNewConnection(
        for addressedEnvelope: AddressedEnvelope<ByteBuffer>,
        sourceConnectionID: QUICConnectionID?,
        destinationConnectionID: QUICConnectionID,
        localAddress: SocketAddress
    ) throws {
        // The original DCID was generated by the client. We'll generate a new one to use as our SCID.
        let newSourceConnectionID: QUICConnectionID
        if let sourceConnectionID {
            newSourceConnectionID = self.connectionIDGenerator.next(
                sourceConnectionID: sourceConnectionID,
                destinationConnectionID: destinationConnectionID
            )
        } else {
            newSourceConnectionID = self.connectionIDGenerator.next()
        }

        // The destination connection ID chosen by the client is the "original" source ID.
        let connectionLogger = {
            var logger = logger
            logger[metadataKey: LoggingKeys.connectionOriginalSCID] =
                "\(destinationConnectionID.description)"
            logger[metadataKey: LoggingKeys.connectionSCID] = "\(newSourceConnectionID)"
            logger[metadataKey: LoggingKeys.connectionDCID] = "\(sourceConnectionID?.description ?? "none")"
            logger[metadataKey: LoggingKeys.addressLocal] = "\(localAddress)"
            logger[metadataKey: LoggingKeys.addressRemote] = "\(addressedEnvelope.remoteAddress)"
            return logger
        }()

        connectionLogger.trace("QUICHandler accepting new connection")
        // Size this connection's packets for the client's Initial, if configured to match it.
        var configuration = self.quicConfiguration
        configuration.initialPacketSize = .fixed(
            configuration.initialPacketSize.size(forClientInitial: addressedEnvelope.data.readableBytes)
        )
        let quicConnection: AcceptedConnection
        do {
            if self.makeConsumer != nil && self.connectionDriver == .stateMachine
                && QUICConnectionDriver.stateMachineSupports(configuration)
            {
                quicConnection = .stateMachine(
                    try StateMachineQUICConnection<Consumer>.server(
                        configuration: configuration,
                        sourceConnectionID: newSourceConnectionID,
                        originalDestinationConnectionID: destinationConnectionID,
                        peerConnectionID: sourceConnectionID,
                        statelessResetTokenGenerator: self.statelessResetTokenGenerator,
                        authenticator: self.authenticator,
                        localAddress: localAddress,
                        remoteAddress: addressedEnvelope.remoteAddress,
                        eventLoop: self.context!.eventLoop,
                        timers: self.timerQueue,
                        logger: connectionLogger
                    )
                )
            } else {
                // The context is set when the channel becomes active so force unwrapping is okay here
                quicConnection = .swiftNetwork(
                    try SwiftNetworkQUICConnection<Consumer>.server(
                        configuration: configuration,
                        sourceConnectionID: newSourceConnectionID,
                        statelessResetTokenGenerator: self.statelessResetTokenGenerator,
                        authenticator: self.authenticator,
                        localAddress: localAddress,
                        remoteAddress: addressedEnvelope.remoteAddress,
                        logger: connectionLogger,
                        eventLoop: self.context!.eventLoop,
                        usesStreamTable: self.makeConsumer != nil
                    )
                )
            }
        } catch {
            // Admission already counted this connection, but its release callbacks are only
            // registered once it exists. Give the slots back here.
            self.connectionAdmissionController.finishedHandshake()
            self.connectionAdmissionController.closingConnection()
            throw error
        }

        let handle = self.nextConnectionHandle()
        let handshakePromise = self.eventLoop.makePromise(of: Void.self)
        let channel: QUICConnectionChannel<Consumer>

        switch self.multiplexerContinuation {
        case .closure(let connectionInitializer, let inboundStreamInitializer, _, let role):
            channel = self.makeQUICConnectionChannel(
                quicConnection: quicConnection,
                handle: handle
            )
            channel.setInboundStreamInitializer(.closure(inboundStreamInitializer))

            let view = channel.transportView
            self.connectionRegistry.insert(view, forHandle: handle, connectionID: newSourceConnectionID)

            // Keep track of the original DCID the peer used in case they retransmit or send
            // additional INITIAL packets.
            // TODO: Remove the DCID alias from multiplexing.
            if newSourceConnectionID != destinationConnectionID {
                self.connectionRegistry.associate(destinationConnectionID, with: handle)
            }

            let streamCreator = channel.makeStreamCreator(role: role)
            let initPromise = self.eventLoop.makePromise(of: Void.self)

            view.initialize(readyPromise: initPromise, handshakePromise: handshakePromise) { ch in
                connectionInitializer(ch, streamCreator)
            }

            initPromise.futureResult.assumeIsolated().whenComplete { result in
                switch result {
                case .success:
                    self.deliverFirstPacket(addressedEnvelope, to: view)
                case .failure:
                    // Nothing to unwind: failing initialization closes the channel, so
                    // 'connectionDidClose' does the teardown.
                    ()
                }
            }

        case .connectionMultiplexerContinuation(let multiplexerContinuation):
            channel = self.makeQUICConnectionChannel(
                quicConnection: quicConnection,
                handle: handle
            )
            let view = channel.transportView
            self.connectionRegistry.insert(view, forHandle: handle, connectionID: newSourceConnectionID)

            // Keep track of the original DCID the peer used in case they retransmit or send
            // additional INITIAL packets.
            // TODO: Remove the DCID alias from multiplexing.
            if newSourceConnectionID != destinationConnectionID {
                self.connectionRegistry.associate(destinationConnectionID, with: handle)
            }

            let outputPromise = self.eventLoop.makePromise(of: (any Sendable).self)
            let initPromise = self.eventLoop.makePromise(of: Void.self)
            initPromise.futureResult.cascadeFailure(to: outputPromise)

            view.initialize(readyPromise: initPromise, handshakePromise: handshakePromise) { _ in
                multiplexerContinuation.initialize(
                    channel: channel,
                    logger: connectionLogger
                ).map { output in
                    outputPromise.succeed(output)
                    return ()
                }
            }

            initPromise.futureResult
                .and(outputPromise.futureResult)
                .assumeIsolated()
                .whenComplete { result in
                    switch result {
                    case .success(let (_, output)):
                        connectionLogger.trace("QUICHandler yielding output to multiplexer")
                        multiplexerContinuation.yield(connection: output)
                        self.deliverFirstPacket(addressedEnvelope, to: view)
                    case .failure:
                        // Nothing to unwind: failing initialization closes the channel, so
                        // 'connectionDidClose' does the teardown.
                        ()
                    }
                }

        case .none:
            // No continuation means the consumer is used.
            channel = self.makeQUICConnectionChannel(quicConnection: quicConnection, handle: handle)
            let view = channel.transportView
            self.connectionRegistry.insert(view, forHandle: handle, connectionID: newSourceConnectionID)

            // Keep track of the original DCID the peer used in case they retransmit or send
            // additional INITIAL packets.
            if newSourceConnectionID != destinationConnectionID {
                self.connectionRegistry.associate(destinationConnectionID, with: handle)
            }

            let initPromise = self.eventLoop.makePromise(of: Void.self)

            view.initialize(readyPromise: initPromise, handshakePromise: handshakePromise) {
                $0.eventLoop.makeSucceededVoidFuture()
            }

            initPromise.futureResult.assumeIsolated().whenComplete { result in
                switch result {
                case .success:
                    self.deliverFirstPacket(addressedEnvelope, to: view)
                case .failure:
                    ()
                }
            }
        }

        handshakePromise.futureResult.assumeIsolated().whenComplete { _ in
            // Make sure we release the slot for new connections.
            self.connectionAdmissionController.finishedHandshake()
        }

        let stateMachineConnection: StateMachineQUICConnection<Consumer>?
        if case .stateMachine(let connection) = quicConnection {
            stateMachineConnection = connection
        } else {
            stateMachineConnection = nil
        }
        channel.closeFuture.assumeIsolated().whenComplete { _ in
            self.connectionAdmissionController.closingConnection()
            self.connectionDidClose(handle, stateMachineConnection: stateMachineConnection)
        }
    }
}

@available(anyAppleOS 26, *)
public struct QUICHandlerHandle: Sendable {
    private let _shutdownGracefully: NIOLoopBound<(NIODeadline) -> EventLoopFuture<Void>>

    internal init<Consumer: QUICStreamConsumer & ~Copyable>(
        wrapping handler: QUICHandler<Consumer>,
        eventLoop: any EventLoop
    ) {
        // Wrap the function to drop the generics.
        let fn: (NIODeadline) -> EventLoopFuture<Void> = {
            handler.shutdownGracefully(deadline: $0)
        }

        self._shutdownGracefully = NIOLoopBound(fn, eventLoop: eventLoop)
    }

    /// Shuts the server down gracefully.
    ///
    /// - Parameters:
    ///     - deadline: Deadline until connections are closed gracefully. Afterwards they will be forcibly closed.
    /// - Returns: A future that is notified once the server is closed.
    public func shutdownGracefully(deadline: NIODeadline) async throws {
        try await self._shutdownGracefully.flatSubmit { $0(deadline) }.get()
    }
}

@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    public func makeHandle() -> QUICHandlerHandle {
        QUICHandlerHandle(wrapping: self, eventLoop: self.eventLoop)
    }
}

@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    internal func writeDatagram(
        _ envelope: AddressedEnvelope<ByteBuffer>,
        promise: EventLoopPromise<Void>?
    ) {
        guard let context = self.context else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        self.logger.trace(
            "QUICHandler writing outbound data",
            metadata: [
                LoggingKeys.addressRemote: "\(envelope.remoteAddress)",
                LoggingKeys.channelOutboundBytes: "\(envelope.data.readableBytes)",
            ]
        )
        self.didWrite = true
        context.write(QUICHandler.wrapOutboundOut(envelope), promise: promise)
    }

    internal func flush() {
        if self.didWrite && !self.expectingChannelReadComplete {
            self.logger.trace("QUICHandler flushing")
            self.didWrite = false
            self.context?.flush()
        }
    }

    internal func read() {
        self.logger.trace("QUICHandler read from child channel")
        self.context?.read()
    }
}

@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    struct ChildView: QUICTransport {
        private let handler: QUICHandler

        init(_ handler: QUICHandler) {
            handler.eventLoop.assertInEventLoop()
            self.handler = handler
        }

        func writeDatagram(
            _ envelope: AddressedEnvelope<ByteBuffer>,
            promise: EventLoopPromise<Void>?
        ) {
            self.handler.writeDatagram(envelope, promise: promise)
        }

        func flush() {
            self.handler.flush()
        }

        func read() {
            self.handler.read()
        }
    }
}

@available(anyAppleOS 26, *)
@available(*, unavailable)
extension QUICHandler.ChildView: Sendable where Consumer: ~Copyable {}

@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    struct RegistrarView: QUICConnectionIDRegistrar {
        private let handler: QUICHandler
        private let handle: ConnectionHandle

        init(_ handler: QUICHandler, handle: ConnectionHandle) {
            handler.eventLoop.assertInEventLoop()
            self.handler = handler
            self.handle = handle
        }

        func associate(_ newID: QUICConnectionID) -> Bool {
            self.handler.connectionRegistry.associate(newID, with: self.handle)
        }

        func retire(_ connectionID: QUICConnectionID) -> Bool {
            self.handler.connectionRegistry.retire(connectionID, from: self.handle)
        }

        func generateID() -> QUICConnectionID {
            self.handler.connectionIDGenerator.next()
        }
    }
}

@available(anyAppleOS 26, *)
@available(*, unavailable)
extension QUICHandler.RegistrarView: Sendable where Consumer: ~Copyable {}

@available(anyAppleOS 26, *)
extension QUICHandler where Consumer: ~Copyable {
    /// A connection accepted from a client's Initial, before its channel exists.
    enum AcceptedConnection {
        case swiftNetwork(SwiftNetworkQUICConnection<Consumer>)
        case stateMachine(StateMachineQUICConnection<Consumer>)
    }

    private func makeQUICConnectionChannel(
        quicConnection: AcceptedConnection,
        handle: ConnectionHandle
    ) -> QUICConnectionChannel<Consumer> {
        switch quicConnection {
        case .swiftNetwork(let connection):
            return self.makeQUICConnectionChannel(quicConnection: connection, handle: handle)
        case .stateMachine(let connection):
            return self.makeQUICConnectionChannel(stateMachineConnection: connection, handle: handle)
        }
    }

    private func makeQUICConnectionChannel(
        stateMachineConnection connection: StateMachineQUICConnection<Consumer>,
        handle: ConnectionHandle
    ) -> QUICConnectionChannel<Consumer> {
        let table = connection.streamTable

        let channel = QUICConnectionChannel(
            udpChannel: self.udpChannel,
            connection: .stateMachine(connection),
            registrar: .live(QUICHandler<Consumer>.RegistrarView(self, handle: handle)),
            transport: .live(QUICHandler<Consumer>.ChildView(self)),
            isServer: connection.role == .server,
            table: table
        )

        if table != nil, let makeConsumer = self.makeConsumer {
            channel.setConsumer(makeConsumer(QUICStreamConnection(channel: channel)))
        }

        return channel
    }

    private func makeQUICConnectionChannel(
        quicConnection: SwiftNetworkQUICConnection<Consumer>,
        handle: ConnectionHandle
    ) -> QUICConnectionChannel<Consumer> {
        let table = quicConnection.streamTable

        let channel = QUICConnectionChannel(
            udpChannel: self.udpChannel,
            connection: .live(quicConnection),
            registrar: .live(QUICHandler<Consumer>.RegistrarView(self, handle: handle)),
            transport: .live(QUICHandler<Consumer>.ChildView(self)),
            isServer: quicConnection.role == .server,
            table: table
        )

        if table != nil, let makeConsumer = self.makeConsumer {
            channel.setConsumer(makeConsumer(QUICStreamConnection(channel: channel)))
        }

        return channel
    }
}

/// An opaque, stable identity for a QUIC connection.
struct ConnectionHandle: Hashable, Sendable {
    private var rawValue: UInt64

    static var initial: ConnectionHandle {
        Self(rawValue: 0)
    }

    private init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    fileprivate mutating func formNext() {
        self.rawValue &+= 1
    }

    func next() -> Self {
        var next = self
        next.formNext()
        return next
    }
}

/// Create a connection admission control for the given connection limits.
@available(anyAppleOS 26, *)
private func makeConnectionAdmissionController(
    for connectionLimits: QUICConnectionLimits,
    logger: Logger,
    eventLoop: any EventLoop
) -> ConnectionAdmissionController {
    switch connectionLimits.mode {
    case .unlimited:
        return ConnectionAdmissionController(
            activeLimit: nil,
            handshakeLimit: nil,
            newConnectionRateLimit: nil,
            eventLoop: eventLoop
        )

    case .perHandler(let activeLimit, let handshakeLimit, let newConnectionRateLimit):
        if activeLimit == 0 || handshakeLimit == 0 || newConnectionRateLimit == 0 {
            logger.warning(
                "QUICConnectionLimits has a limit of 0; this handler rejects every new connection (use nil for no limit)",
                metadata: [
                    LoggingKeys.connectionLimitActive: "\(activeLimit?.description ?? "none")",
                    LoggingKeys.connectionLimitHandshake: "\(handshakeLimit?.description ?? "none")",
                    LoggingKeys.connectionLimitNewConnectionRate: "\(newConnectionRateLimit?.description ?? "none")",
                ]
            )
        }
        if let activeLimit, let handshakeLimit, handshakeLimit > activeLimit {
            logger.warning(
                "QUICConnectionLimits handshakeLimit is looser than activeLimit; the active limit binds first, so the handshake limit has no effect",
                metadata: [
                    LoggingKeys.connectionLimitActive: "\(activeLimit)",
                    LoggingKeys.connectionLimitHandshake: "\(handshakeLimit)",
                ]
            )
        }

        return ConnectionAdmissionController(
            activeLimit: activeLimit,
            handshakeLimit: handshakeLimit,
            newConnectionRateLimit: newConnectionRateLimit,
            eventLoop: eventLoop
        )
    }
}

/// The implementation that drives a connection.
@available(anyAppleOS 26, *)
enum QUICConnectionDriver: Hashable, Sendable {
    /// The SwiftNetwork framework's `QUICConnection`.
    case swiftNetwork
    /// SwiftNetwork's `StandaloneQUICConnection`, driven directly. Only connections that serve a stream
    /// consumer, with a configuration it ``stateMachineSupports(_:)``, can use it; the others fall back to
    /// ``swiftNetwork``.
    case stateMachine

    /// The default for a role: ``stateMachine``, unless the `NIOQUIC_DRIVER` environment variable
    /// says otherwise. `swift-network` selects ``swiftNetwork`` for both roles,
    /// `state-machine-server` and `state-machine-client` keep the state machine for one role only.
    static func `default`(for role: Role) -> Self {
        switch Self.setting {
        case "swift-network":
            return .swiftNetwork
        case "state-machine-server":
            return role == .server ? .stateMachine : .swiftNetwork
        case "state-machine-client":
            return role == .client ? .stateMachine : .swiftNetwork
        default:
            return .stateMachine
        }
    }

    /// The ``QUICConfiguration`` properties the state machine driver implements, whatever their
    /// value. A configuration that sets any other property to something but its default falls back
    /// to ``swiftNetwork``, see ``stateMachineSupports(_:)``.
    static let stateMachineProperties: Set<String> = [
        "role",
        // TLS: the drivers make the same `SwiftTLSProtocol.Options`.
        "keyExchangeGroup", "applicationProtocols", "serverName", "authenticationConfiguration",
        "peerCertificateVerification", "verificationConfiguration",
        // Transport parameters and the connection's own settings.
        "initialMaxData", "initialMaxStreamDataBidiLocal", "initialMaxStreamDataBidiRemote",
        "initialMaxStreamDataUni", "initialMaxStreamsBidi", "initialMaxStreamsUni", "maxIdleTimeout",
        "keepAliveInterval", "maxDatagramFrameSize", "initialPacketSize", "forceVersionNegotiation",
    ]

    /// The ``QUICConfiguration`` properties the state machine driver implements only at their
    /// defaults: it sends no Retry, and writes no key log or qlog. ``stateMachineSupports(_:)``
    /// checks each.
    ///
    /// Together with ``stateMachineProperties`` these are all of the configuration's properties;
    /// a test checks that a new one is added to either.
    static let stateMachineDefaultOnlyProperties: Set<String> = ["keyLogPath", "qLogConfiguration", "sendRetry"]

    /// Whether the state machine driver implements everything `configuration` asks for: the
    /// ``stateMachineProperties`` at any value, and the ``stateMachineDefaultOnlyProperties`` at
    /// their defaults.
    static func stateMachineSupports(_ configuration: QUICConfiguration) -> Bool {
        configuration.keyLogPath == nil && configuration.qLogConfiguration == nil && !configuration.sendRetry
    }

    private static let setting: String? = {
        guard let value = getenv("NIOQUIC_DRIVER") else { return nil }
        return String(cString: value)
    }()
}
