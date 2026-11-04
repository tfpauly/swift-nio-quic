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

import NIOCore
import Testing

@_spi(ProtocolProvider) @testable import NIOQUIC
@_spi(ProtocolProvider) @testable import SwiftNetwork

struct OutputDatagramTests {
    /// Writes `bytes` at the start of the frame, as the connection does, and claims the rest.
    @available(anyAppleOS 26, *)
    private func fill(_ frame: inout Frame, with bytes: [UInt8]) {
        frame.span?.withUnsafeBufferPointer { _ in }
        if let pointer = frame.unsafeUnclaimedBuffer {
            pointer.copyBytes(from: bytes)
        }
        _ = frame.claim(fromStart: 0, fromEnd: frame.unclaimedLength - bytes.count)
    }

    @available(anyAppleOS 26, *)
    @Test
    func aDatagramIsASliceOfTheArenaWithItsBytes() {
        let allocator = ByteBufferAllocator()
        let output = OutputDatagram(allocator: allocator)
        var frame = output.makeFrame(size: 1200)
        self.fill(&frame, with: [1, 2, 3, 4, 5])
        let datagram = OutputDatagram.datagram(from: frame, allocator: allocator)
        #expect(datagram?.readableBytesView.elementsEqual([1, 2, 3, 4, 5]) == true)
        frame.finalize(success: true)
    }

    @available(anyAppleOS 26, *)
    @Test
    func framesInOneArenaDoNotOverlap() {
        let allocator = ByteBufferAllocator()
        let output = OutputDatagram(allocator: allocator)
        var first = output.makeFrame(size: 1200)
        var second = output.makeFrame(size: 1200)
        self.fill(&first, with: Array(repeating: 0xAA, count: 40))
        self.fill(&second, with: Array(repeating: 0xBB, count: 40))
        let a = OutputDatagram.datagram(from: first, allocator: allocator)
        let b = OutputDatagram.datagram(from: second, allocator: allocator)
        #expect(a?.readableBytesView.allSatisfy { $0 == 0xAA } == true)
        #expect(b?.readableBytesView.allSatisfy { $0 == 0xBB } == true)
        first.finalize(success: true)
        second.finalize(success: true)
    }

    @available(anyAppleOS 26, *)
    @Test
    func theUnusedEndOfTheLatestFrameIsReused() {
        let allocator = ByteBufferAllocator()
        let output = OutputDatagram(allocator: allocator)
        // Many small datagrams, one at a time, as acknowledgements are: far more than an arena of
        // whole packets would hold.
        var slices: [ByteBuffer] = []
        for i in 0..<200 {
            var frame = output.makeFrame(size: 1200)
            self.fill(&frame, with: [UInt8](repeating: UInt8(i & 0xFF), count: 40))
            slices.append(OutputDatagram.datagram(from: frame, allocator: allocator)!)
            frame.finalize(success: true)
        }
        // None was overwritten by a later one.
        for (i, slice) in slices.enumerated() {
            #expect(slice.readableBytes == 40)
            #expect(slice.readableBytesView.allSatisfy { $0 == UInt8(i & 0xFF) })
        }
    }

    @available(anyAppleOS 26, *)
    @Test
    func aFullArenaIsReplaced() {
        let allocator = ByteBufferAllocator()
        let output = OutputDatagram(allocator: allocator)
        var frames = FrameArray(capacity: 40)
        for _ in 0..<40 { frames.add(frame: output.makeFrame(size: 1200)) }
        // 40 frames of 1200 bytes do not fit one arena; all of them are usable and distinct.
        var datagrams: [ByteBuffer] = []
        var index = 0
        frames.iterateMutableFrames { frame -> FrameArray.FrameIterationResult in
            self.fill(&frame, with: [UInt8](repeating: UInt8(index), count: 10))
            datagrams.append(OutputDatagram.datagram(from: frame, allocator: allocator)!)
            index += 1
            frame.finalize(success: true)
            return .removeFrameAndContinue
        }
        #expect(datagrams.count == 40)
        for (i, datagram) in datagrams.enumerated() {
            #expect(datagram.readableBytesView.allSatisfy { $0 == UInt8(i) })
        }
    }

    @available(anyAppleOS 26, *)
    @Test
    func aFrameThatIsNotOursIsCopied() {
        let allocator = ByteBufferAllocator()
        var frame = Frame(copyBuffer: [9, 8, 7])
        let datagram = OutputDatagram.datagram(from: frame, allocator: allocator)
        #expect(datagram?.readableBytesView.elementsEqual([9, 8, 7]) == true)
        frame.finalize(success: true)
    }

    @available(anyAppleOS 26, *)
    @Test
    func anEmptyFrameHasNoDatagram() {
        let allocator = ByteBufferAllocator()
        let output = OutputDatagram(allocator: allocator)
        var frame = output.makeFrame(size: 100)
        _ = frame.claim(fromStart: 100)
        #expect(OutputDatagram.datagram(from: frame, allocator: allocator) == nil)
        frame.finalize(success: true)
    }
}
