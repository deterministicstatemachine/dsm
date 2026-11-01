// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest
@testable import DsmWallet

final class EventRelayTests: XCTestCase {
    /// Events posted before the page is ready wait, and replay in arrival
    /// order once it is; one the page does not take stays, with every one
    /// after it, so the order the events arrived in is the order the page
    /// sees them in.
    func testEventsWaitForThePageAndReplayInOrder() {
        let relay = EventRelay()
        var taken: [String] = []
        var refuse = Set<String>()
        relay.attach { event in
            guard case .topic(let topic, _) = event else { return taken.count < 0 }
            if refuse.contains(topic) { return taken.count < 0 }
            taken.append(topic)
            return taken.count > 0
        }
        relay.post(topic: "first", payload: Data([1]))
        relay.post(topic: "second", payload: Data([2]))
        XCTAssertEqual(taken, [])
        XCTAssertEqual(relay.pendingCount, 2)

        refuse.insert("second")
        relay.markReady()
        XCTAssertEqual(taken, ["first"])
        XCTAssertEqual(relay.pendingCount, 1)

        relay.post(topic: "third", payload: Data([3]))
        XCTAssertEqual(taken, ["first"], "nothing passes the event the page did not take")
        XCTAssertEqual(relay.pendingCount, 2)

        refuse.remove("second")
        relay.flush()
        XCTAssertEqual(taken, ["first", "second", "third"])
        XCTAssertEqual(relay.pendingCount, 0)

        relay.markNotReady()
        relay.post(topic: "fourth", payload: Data([4]))
        XCTAssertEqual(taken, ["first", "second", "third"])
        XCTAssertEqual(relay.pendingCount, 1)
    }

    /// An event the page did not take is handed over again when the next one
    /// arrives, and the one that arrived follows it: nothing waits for a
    /// second markReady.
    func testAnEventKeptIsRetriedOnTheNextPost() {
        let relay = EventRelay()
        var taken: [String] = []
        var refuse = Set<String>()
        relay.attach { event in
            guard case .topic(let topic, _) = event, !refuse.contains(topic) else { return taken.count < 0 }
            taken.append(topic)
            return taken.count > 0
        }
        relay.markReady()
        refuse.insert("held")
        relay.post(topic: "held", payload: Data([1]))
        XCTAssertEqual(relay.pendingCount, 1)
        refuse.remove("held")
        relay.post(topic: "after", payload: Data([2]))
        XCTAssertEqual(taken, ["held", "after"])
        XCTAssertEqual(relay.pendingCount, 0)
    }
}
