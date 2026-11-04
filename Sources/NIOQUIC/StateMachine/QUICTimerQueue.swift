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

@_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetwork

/// Where an owner is in its queue's heap, or `-1` if it has no deadline queued.
///
/// The heap moves entries around and keeps every owner's index current. Writing the index through
/// the owner's protocol makes the compiler retain and release the owner around each write, as the
/// write could run any code; a final class with one stored property has no such cost.
@available(anyAppleOS 26, *)
final class QUICTimerSlot {
    var index = -1
}

@available(anyAppleOS 26, *)
extension QUICTimerOwner {
    var timerQueueIndex: Int { self.timerSlot.index }
}

/// Something that has a deadline in a ``QUICTimerQueue``.
@available(anyAppleOS 26, *)
protocol QUICTimerOwner: AnyObject {
    /// Where the owner is in the queue's heap. Only the queue sets it.
    var timerSlot: QUICTimerSlot { get }

    /// The owner's deadline has passed.
    func timerDue()
}

/// The deadlines of all the connections on one event loop, behind a single NIO task.
///
/// A connection used to schedule a `ScheduledTask` of its own whenever its next deadline moved
/// earlier, which costs an allocation for the task and its promise and a cancel for the one it
/// replaces, for every connection. With thousands of connections on a loop, almost every new
/// deadline falls after one that is already queued, so the queue only touches the NIO task when the
/// earliest deadline changes: one task per event loop, not one per connection.
///
/// The queue is a binary min-heap that tracks where each owner is, so an owner has at most one
/// entry (moved earlier when it needs to be, removed when it is done) and a closed connection is
/// not kept alive by a deadline it no longer needs.
///
/// It is also the loop's clock for the connections: while the loop works through a batch of
/// datagrams or timers, every connection sees the time the batch began, which saves each of them
/// several reads of the system clock.
@available(anyAppleOS 26, *)
final class QUICTimerQueue {
    private struct Entry {
        var deadline: NIODeadline
        var owner: any QUICTimerOwner
        let slot: QUICTimerSlot
    }

    private var heap: [Entry] = []
    private let eventLoop: any EventLoop
    private var task: Scheduled<Void>?
    private var taskDeadline: NIODeadline?
    private var due: [any QUICTimerOwner] = []
    private var batchNow: NetworkClock.Instant?
    private var firing = false

    /// Reads the loop's clock; the system's, unless a test drives a loop's time itself.
    private let readClock: () -> NIODeadline

    init(eventLoop: any EventLoop, clock: @escaping () -> NIODeadline = { NIODeadline.now() }) {
        self.eventLoop = eventLoop
        self.readClock = clock
    }

    // MARK: Clock

    /// The current time: the time the current batch began, if there is one.
    var now: NetworkClock.Instant {
        self.batchNow ?? self.systemNow
    }

    private var systemNow: NetworkClock.Instant {
        NetworkClock.Instant.zero.advanced(by: .microseconds(Int64(self.readClock().uptimeNanoseconds / 1000)))
    }

    /// Fixes the time for the connections that work until `endBatch()`.
    func beginBatch() {
        self.batchNow = self.systemNow
    }

    func endBatch() {
        self.batchNow = nil
    }

    // MARK: Deadlines

    /// Makes sure `owner` is called no later than `deadline`. An earlier deadline of the owner's
    /// stays: it fires early if need be, and the owner arms the real one then.
    func arm(_ owner: some QUICTimerOwner, deadline: NIODeadline) {
        let index = owner.timerSlot.index
        if index >= 0 {
            guard deadline < self.heap[index].deadline else { return }
            self.heap[index].deadline = deadline
            self.siftUp(index)
        } else {
            self.heap.append(Entry(deadline: deadline, owner: owner, slot: owner.timerSlot))
            owner.timerSlot.index = self.heap.count - 1
            self.siftUp(self.heap.count - 1)
        }
        self.armTask()
    }

    /// Drops `owner`'s deadline, if it has one.
    func remove(_ owner: some QUICTimerOwner) {
        let index = owner.timerSlot.index
        guard index >= 0 else { return }
        self.removeEntry(at: index)
    }

    /// Stops the loop's task and forgets every deadline.
    func cancelAll() {
        self.task?.cancel()
        self.task = nil
        self.taskDeadline = nil
        for entry in self.heap { entry.slot.index = -1 }
        self.heap.removeAll()
    }

    // MARK: The loop's task

    private func armTask() {
        // While owners run, the task is set once at the end, for whatever is earliest then.
        guard !self.firing, let first = self.heap.first else { return }
        // A task that fires at or before the earliest deadline is enough: it re-arms itself.
        if let current = self.taskDeadline, self.task != nil, current <= first.deadline { return }
        self.task?.cancel()
        self.taskDeadline = first.deadline
        self.task = self.eventLoop.assumeIsolated().scheduleTask(deadline: first.deadline) {
            self.fire()
        }
    }

    private func fire() {
        self.task = nil
        self.taskDeadline = nil
        let now = self.readClock()
        // The owners that are due now are taken out before any of them runs, so one that arms
        // itself for a time already past waits for the next turn of the loop.
        while let first = self.heap.first, first.deadline <= now {
            self.due.append(first.owner)
            self.removeEntry(at: 0)
        }
        if !self.due.isEmpty {
            self.firing = true
            self.beginBatch()
            for owner in self.due { owner.timerDue() }
            self.endBatch()
            self.firing = false
            self.due.removeAll(keepingCapacity: true)
        }
        self.armTask()
    }

    // MARK: Heap

    private func removeEntry(at index: Int) {
        let last = self.heap.count - 1
        self.heap[index].slot.index = -1
        if index == last {
            self.heap.removeLast()
            return
        }
        self.heap.swapAt(index, last)
        self.heap.removeLast()
        self.heap[index].slot.index = index
        self.siftDown(index)
        self.siftUp(index)
    }

    private func siftUp(_ start: Int) {
        var child = start
        while child > 0 {
            let parent = (child - 1) / 2
            guard self.heap[child].deadline < self.heap[parent].deadline else { break }
            self.swap(child, parent)
            child = parent
        }
    }

    private func siftDown(_ start: Int) {
        var parent = start
        let count = self.heap.count
        while true {
            let left = 2 * parent + 1
            if left >= count { break }
            let right = left + 1
            let smaller = (right < count && self.heap[right].deadline < self.heap[left].deadline) ? right : left
            guard self.heap[smaller].deadline < self.heap[parent].deadline else { break }
            self.swap(smaller, parent)
            parent = smaller
        }
    }

    private func swap(_ a: Int, _ b: Int) {
        self.heap.swapAt(a, b)
        self.heap[a].slot.index = a
        self.heap[b].slot.index = b
    }
}
