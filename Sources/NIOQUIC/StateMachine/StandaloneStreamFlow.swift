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

@_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetwork

/// What the standalone connection driver keeps for one stream.
///
/// The stream's slot in the stream table holds a reference to it, so the stream's operations reach
/// the driver's state without a lookup. It is not generic, so none of this needs type metadata at
/// runtime.
@available(anyAppleOS 26, *)
@usableFromInline
final class StandaloneStreamFlow {
    let flowID: StandaloneFlowID
    /// The QUIC stream ID, once the stack has assigned it.
    var streamID: UInt64?
    /// Received frames the consumer has not taken yet.
    var pending = FrameArray()
    /// Whether the peer's FIN has been moved into `pending`.
    var sawFin = false

    init(flowID: StandaloneFlowID) {
        self.flowID = flowID
    }

    /// Lets go of the frames the consumer has not taken.
    func discardPending() {
        if !self.pending.isEmpty { self.pending.finalizeAllFramesAsFailed() }
    }
}

/// The streams of a connection by flow, for the events that name a flow.
///
/// A flow ID carries the position of the flow's link, which the stack reuses once the flow is
/// released, so the live flows sit at small positions: this is an array indexed by that position, with
/// no hashing. The ID itself is checked against the entry found there, so the ID of a released flow
/// finds nothing, even once a new flow has taken its position.
///
/// It holds the stream's handle in the stream table, which owns the flow: finding a stream by flow
/// takes no reference count.
@available(anyAppleOS 26, *)
struct StandaloneFlowWindow {
    private struct Entry {
        var flowID: StandaloneFlowID?
        var handle: QUICStreamHandle
    }

    private var items: ContiguousArray<Entry> = []

    subscript(_ id: StandaloneFlowID) -> QUICStreamHandle? {
        let index = id.slotIndex
        guard index < self.items.count, self.items[index].flowID == id else { return nil }
        return self.items[index].handle
    }

    mutating func insert(_ id: StandaloneFlowID, _ handle: QUICStreamHandle) {
        let index = id.slotIndex
        while self.items.count <= index {
            self.items.append(Entry(flowID: nil, handle: handle))
        }
        self.items[index] = Entry(flowID: id, handle: handle)
    }

    @discardableResult
    mutating func remove(_ id: StandaloneFlowID) -> QUICStreamHandle? {
        let index = id.slotIndex
        guard index < self.items.count, self.items[index].flowID == id else { return nil }
        self.items[index].flowID = nil
        return self.items[index].handle
    }

    var isEmpty: Bool {
        !self.items.contains { $0.flowID != nil }
    }
}
