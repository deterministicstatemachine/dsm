// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// Events for the page, from Rust and from the host, in arrival order.
///
/// Until the page is ready, and after a delivery the page did not take, the
/// events wait here and are replayed by `flush`, oldest first; one the page
/// did not take stays, with every one after it, so the order they arrived in
/// is the order the page sees them in. Android spools these in SQLite because
/// its BLE service outlives the activity; on iOS the radio runs only while
/// the app is open, so nothing arrives with no page process to hold it, and
/// the spool is in memory. The queue is capped: past the cap the oldest
/// event is dropped, and the drop is logged.
final class EventRelay {
    static let shared = EventRelay()

    /// An event for the page: a topic with payload bytes, or a NativeHostEvent's bytes.
    enum Event {
        case topic(String, Data)
        case nativeHost(Data)
    }

    /// Whether the page can take events: it says so once its port is up.
    private enum Readiness { case waiting, ready }

    private static let maxQueued = 200
    private let lock = NSLock()
    private var queue: [Event] = []
    private var readiness = Readiness.waiting
    /// Hands one event to the page; answers whether the page took it.
    private var deliver: ((Event) -> Bool)?

    /// The page's web view attaches its deliverer; nothing is marked ready by it.
    func attach(deliver: @escaping (Event) -> Bool) {
        lock.lock()
        self.deliver = deliver
        lock.unlock()
    }

    /// The page can take events now: replay what waited.
    func markReady() {
        lock.lock()
        readiness = .ready
        lock.unlock()
        flush()
    }

    /// The page is gone (its view was torn down): hold events again.
    func markNotReady() {
        lock.lock()
        readiness = .waiting
        lock.unlock()
    }

    func post(topic: String, payload: Data) {
        post(.topic(topic, payload))
    }

    func post(nativeHostEvent: Data) {
        post(.nativeHost(nativeHostEvent))
    }

    private func post(_ event: Event) {
        lock.lock()
        let deliverNow = readiness == .ready && queue.isEmpty
        let deliverer = deliver
        if !deliverNow {
            enqueueLocked(event)
        }
        lock.unlock()
        guard deliverNow, let deliverer else { return }
        if !deliverer(event) {
            lock.lock()
            // The page did not take it: it waits at the front, in order.
            queue.insert(event, at: 0)
            lock.unlock()
        }
    }

    /// The next queued event with the deliverer to take it, while the page is ready.
    private func nextToDeliver() -> (Event, (Event) -> Bool)? {
        lock.lock()
        defer { lock.unlock() }
        guard readiness == .ready, let deliverer = deliver, let next = queue.first else { return nil }
        return (next, deliverer)
    }

    /// Replays queued events in order until one is not taken.
    func flush() {
        while let (next, deliverer) = nextToDeliver() {
            if !deliverer(next) { return }
            lock.lock()
            if !queue.isEmpty { queue.removeFirst() }
            lock.unlock()
        }
    }

    /// How many events wait for the page.
    var pendingCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return queue.count
    }

    private func enqueueLocked(_ event: Event) {
        if queue.count >= EventRelay.maxQueued {
            queue.removeFirst()
            DsmLog.warn("EventRelay", "the event queue is full; the oldest event was dropped")
        }
        queue.append(event)
    }
}
