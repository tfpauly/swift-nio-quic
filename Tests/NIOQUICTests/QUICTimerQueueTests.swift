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
import NIOEmbedded
import Testing

@testable import NIOQUIC

struct QUICTimerQueueTests {
    @available(anyAppleOS 26, *)
    private final class Owner: QUICTimerOwner {
        let timerSlot = QUICTimerSlot()
        var fired: [String] = []
        let name: String
        let log: Log
        var onDue: (() -> Void)?
        final class Log { var order: [String] = [] }

        init(_ name: String, log: Log) {
            self.name = name
            self.log = log
        }

        func timerDue() {
            self.log.order.append(self.name)
            self.onDue?()
        }
    }

    @available(anyAppleOS 26, *)
    /// A queue on an embedded loop, whose clock follows the loop's time.
    private func make() -> (QUICTimerQueue, TestLoop, Owner.Log) {
        let loop = TestLoop()
        return (QUICTimerQueue(eventLoop: loop.loop, clock: { loop.now }), loop, Owner.Log())
    }

    private final class TestLoop {
        let loop = EmbeddedEventLoop()
        var now = NIODeadline.uptimeNanoseconds(0)
        func advanceTime(to deadline: NIODeadline) {
            self.now = deadline
            self.loop.advanceTime(to: deadline)
        }
        func run() { self.loop.run() }
    }

    @available(anyAppleOS 26, *)
    @Test
    func ownersFireInDeadlineOrder() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log), b = Owner("b", log: log), c = Owner("c", log: log)
        queue.arm(c, deadline: .uptimeNanoseconds(30))
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        queue.arm(b, deadline: .uptimeNanoseconds(20))
        loop.advanceTime(to: .uptimeNanoseconds(40))
        #expect(log.order == ["a", "b", "c"])
        #expect(a.timerQueueIndex == -1 && b.timerQueueIndex == -1 && c.timerQueueIndex == -1)
    }

    @available(anyAppleOS 26, *)
    @Test
    func aLaterDeadlineLeavesTheEarlierOne() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log)
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        queue.arm(a, deadline: .uptimeNanoseconds(50))
        loop.advanceTime(to: .uptimeNanoseconds(10))
        #expect(log.order == ["a"])
    }

    @available(anyAppleOS 26, *)
    @Test
    func anEarlierDeadlineMovesTheEntry() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log), b = Owner("b", log: log)
        queue.arm(a, deadline: .uptimeNanoseconds(50))
        queue.arm(b, deadline: .uptimeNanoseconds(30))
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        loop.advanceTime(to: .uptimeNanoseconds(10))
        #expect(log.order == ["a"])
        loop.advanceTime(to: .uptimeNanoseconds(30))
        #expect(log.order == ["a", "b"])
    }

    @available(anyAppleOS 26, *)
    @Test
    func aRemovedOwnerDoesNotFire() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log), b = Owner("b", log: log), c = Owner("c", log: log)
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        queue.arm(b, deadline: .uptimeNanoseconds(20))
        queue.arm(c, deadline: .uptimeNanoseconds(30))
        queue.remove(a)
        queue.remove(c)
        queue.remove(c)  // removing twice is fine
        loop.advanceTime(to: .uptimeNanoseconds(100))
        #expect(log.order == ["b"])
    }

    @available(anyAppleOS 26, *)
    @Test
    func anOwnerThatRearmsInItsCallbackFiresAgainLater() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log)
        var fires = 0
        a.onDue = {
            fires += 1
            if fires < 3 { queue.arm(a, deadline: .uptimeNanoseconds(UInt64(100 * (fires + 1)))) }
        }
        queue.arm(a, deadline: .uptimeNanoseconds(100))
        loop.advanceTime(to: .uptimeNanoseconds(100))
        #expect(fires == 1)
        loop.advanceTime(to: .uptimeNanoseconds(200))
        #expect(fires == 2)
        loop.advanceTime(to: .uptimeNanoseconds(300))
        #expect(fires == 3)
        #expect(a.timerQueueIndex == -1)
    }

    @available(anyAppleOS 26, *)
    @Test
    func anOwnerThatRearmsForThePastRunsAgainThroughTheLoopNotInsideTheCall() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log)
        var fires = 0
        var depth = 0
        var deepest = 0
        a.onDue = {
            depth += 1
            deepest = max(deepest, depth)
            fires += 1
            if fires < 5 { queue.arm(a, deadline: .uptimeNanoseconds(1)) }
            depth -= 1
        }
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        loop.advanceTime(to: .uptimeNanoseconds(10))
        loop.run()
        #expect(fires == 5)
        // Each call came from a turn of the loop: none ran inside another.
        #expect(deepest == 1)
    }

    @available(anyAppleOS 26, *)
    @Test
    func theClockIsFixedWithinABatch() {
        let (queue, _, _) = self.make()
        queue.beginBatch()
        let first = queue.now
        var spin = 0
        while spin < 100_000 { spin += 1 }
        #expect(queue.now == first)
        queue.endBatch()
        #expect(queue.now >= first)
    }

    @available(anyAppleOS 26, *)
    @Test
    func cancelAllForgetsEveryDeadline() {
        let (queue, loop, log) = self.make()
        let a = Owner("a", log: log), b = Owner("b", log: log)
        queue.arm(a, deadline: .uptimeNanoseconds(10))
        queue.arm(b, deadline: .uptimeNanoseconds(20))
        queue.cancelAll()
        loop.advanceTime(to: .uptimeNanoseconds(100))
        #expect(log.order.isEmpty)
        #expect(a.timerQueueIndex == -1 && b.timerQueueIndex == -1)
    }
}
