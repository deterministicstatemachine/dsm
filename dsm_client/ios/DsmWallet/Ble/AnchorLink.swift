// SPDX-License-Identifier: MIT OR Apache-2.0
import CoreBluetooth
import DsmSdk
import Foundation

/// This device's link to its anchor board over Bluetooth Low Energy: the
/// board's DSM anchor service, reached as a central. Rust hands it one
/// request frame at a time and takes the answer frame's body back; nothing
/// here reads a byte of either. The board is powered by whatever it is
/// plugged into (this iPad's USB port, say) and talks only over the radio,
/// since iOS gives an app no USB.
///
/// A request frame goes to the `request` characteristic in chunks of what
/// one write carries; the answer comes back as notifications of the `answer`
/// characteristic, LE32 length first, and is complete when that many bytes
/// have arrived. The board serves one frame at a time, so one exchange runs
/// at a time here too. Rust calls on its blocking relay thread; CoreBluetooth
/// works on its own queue, and the caller waits on semaphores.
final class AnchorLink: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    static let shared = AnchorLink()

    static let serviceUUID = CBUUID(string: "d5a10000-7d51-4d00-a04c-00000000d5a1")
    static let requestUUID = CBUUID(string: "d5a10001-7d51-4d00-a04c-00000000d5a1")
    static let answerUUID = CBUUID(string: "d5a10002-7d51-4d00-a04c-00000000d5a1")

    /// How long a board gets to appear and connect when none is linked.
    static let reachTimeout = DispatchTimeInterval.seconds(20)
    /// How long the board gets to answer a frame. Its longest work, a try-run, takes under a
    /// minute; the owner's authorization frame of 49,896 bytes crosses in under ten seconds.
    static let answerTimeout = DispatchTimeInterval.seconds(150)
    /// How long one chunk waits for the radio to take another write.
    static let writeReadyTimeout = DispatchTimeInterval.seconds(5)

    private let tag = "AnchorLink"
    private let queue = DispatchQueue(label: "dsm.anchor.link")
    /// One exchange at a time: the board serves one frame at a time.
    private let turn = NSLock()

    private var central: CBCentralManager?
    private var board: CBPeripheral?
    private var request: CBCharacteristic?
    private var answer: CBCharacteristic?

    /// Signalled when the radio is on or found to be off.
    private let radioKnown = DispatchSemaphore(value: 0)
    /// Signalled when the link is usable or its reach failed.
    private let linked = DispatchSemaphore(value: 0)
    /// Signalled when the board can take another write without response.
    private let writeReady = DispatchSemaphore(value: 0)
    /// Signalled when an answer frame is complete or the link dropped.
    private let answered = DispatchSemaphore(value: 0)

    private var reachFailure: String?
    private var inbound = Data()
    private var exchangeFailure: String?

    /// Install this link as the SDK's anchor appliance transport. Answers
    /// nothing, or why Rust refused it.
    static func install() -> String? {
        DsmSdk.reason(dsm_ffi_install_anchor_link({ request, len, out in
            AnchorLink.shared.transceive(request, len, out)
        }))
    }

    // MARK: The round-trip Rust calls

    /// One frame to the board and its answer's body back, in a buffer Rust
    /// owns. Answers 0, or 1 with the reason in the buffer.
    private func transceive(_ request: UnsafePointer<UInt8>?, _ len: Int, _ out: UnsafeMutablePointer<DsmBytes>?) -> Int32 {
        guard let out else { return 2 }
        let frame = request.map { Data(bytes: $0, count: len) } ?? Data()
        turn.lock()
        defer { turn.unlock() }
        do {
            let body = try exchange(frame)
            out.pointee = AnchorLink.buffer(body)
            return 0
        } catch let failure as LinkFailure {
            DsmLog.warn(tag, "the board did not answer: \(failure.why)")
            BridgeLogger.logRadio("anchor link: \(failure.why)")
            out.pointee = AnchorLink.buffer(Data(failure.why.utf8))
            return 1
        } catch {
            out.pointee = AnchorLink.buffer(Data("\(error)".utf8))
            return 1
        }
    }

    /// Bytes in a buffer Rust allocated and will free.
    private static func buffer(_ data: Data) -> DsmBytes {
        var buffer = dsm_bytes_alloc(data.count)
        if let ptr = buffer.ptr {
            data.copyBytes(to: ptr, count: data.count)
        }
        buffer.len = data.count
        return buffer
    }

    struct LinkFailure: Error {
        let why: String
    }

    /// Write `frame` to the board and take its answer frame's body.
    private func exchange(_ frame: Data) throws -> Data {
        drain(answered)
        drain(writeReady)
        try reach()
        guard let board, let request else {
            throw LinkFailure(why: "the board link closed before the frame went out")
        }
        queue.sync {
            inbound.removeAll(keepingCapacity: true)
            exchangeFailure = nil
        }
        let chunk = board.maximumWriteValueLength(for: .withoutResponse)
        var offset = 0
        while offset < frame.count {
            let end = min(offset + chunk, frame.count)
            try write(frame.subdata(in: offset..<end), to: request, on: board)
            offset = end
        }
        return try awaitAnswer()
    }

    /// One chunk, once the board can take a write without response.
    private func write(_ chunk: Data, to request: CBCharacteristic, on board: CBPeripheral) throws {
        var attempts = 0
        while attempts < 3 {
            attempts += 1
            let sent: Bool = queue.sync {
                guard exchangeFailure == nil, board.canSendWriteWithoutResponse else { return false }
                board.writeValue(chunk, for: request, type: .withoutResponse)
                return true
            }
            if sent { return }
            if let why = queue.sync(execute: { exchangeFailure }) {
                throw LinkFailure(why: why)
            }
            if writeReady.wait(timeout: .now() + AnchorLink.writeReadyTimeout) == .timedOut {
                continue
            }
        }
        throw LinkFailure(why: "the board stopped taking the frame")
    }

    /// The answer frame, once its LE32 length and that many bytes are in.
    private func awaitAnswer() throws -> Data {
        if answered.wait(timeout: .now() + AnchorLink.answerTimeout) == .timedOut {
            throw LinkFailure(why: "the board gave no answer in time")
        }
        return try queue.sync {
            if let why = exchangeFailure {
                throw LinkFailure(why: why)
            }
            guard inbound.count >= 4 else {
                throw LinkFailure(why: "the board's answer carried no length")
            }
            let length = Int(inbound[0]) | Int(inbound[1]) << 8 | Int(inbound[2]) << 16 | Int(inbound[3]) << 24
            guard inbound.count == 4 + length else {
                throw LinkFailure(why: "the board's answer was \(inbound.count - 4) of \(length) bytes")
            }
            return inbound.subdata(in: 4..<inbound.count)
        }
    }

    // MARK: Reaching the board

    /// A usable link: the radio on, a board with the DSM anchor service
    /// connected, its characteristics found, its answers subscribed.
    private func reach() throws {
        let usable: Bool = queue.sync {
            if central == nil {
                central = CBCentralManager(delegate: self, queue: queue)
            }
            return board?.state == .connected && request != nil && answer?.isNotifying == true
        }
        if usable { return }
        let state: CBManagerState = queue.sync { central?.state ?? .unknown }
        if state == .unknown || state == .resetting {
            if radioKnown.wait(timeout: .now() + .seconds(5)) == .timedOut {
                throw LinkFailure(why: "Bluetooth did not report its state")
            }
        }
        let on: Bool = queue.sync { central?.state == .poweredOn }
        guard on else {
            throw LinkFailure(why: "Bluetooth is off or not permitted")
        }
        drain(linked)
        queue.sync {
            reachFailure = nil
            board = nil
            request = nil
            answer = nil
            central?.scanForPeripherals(withServices: [AnchorLink.serviceUUID], options: nil)
        }
        BridgeLogger.logRadio("anchor link: scanning for a DSM Anchor")
        let found = linked.wait(timeout: .now() + AnchorLink.reachTimeout)
        queue.sync { central?.stopScan() }
        if found == .timedOut {
            queue.sync {
                if let board { central?.cancelPeripheralConnection(board) }
                board = nil
            }
            throw LinkFailure(why: "no DSM Anchor answered within \(AnchorLink.reachTimeout)")
        }
        if let why = queue.sync(execute: { reachFailure }) {
            throw LinkFailure(why: why)
        }
    }

    /// Take every signal a semaphore holds from an earlier exchange, so a wait answers to this one.
    private func drain(_ semaphore: DispatchSemaphore) {
        while semaphore.wait(timeout: .now()) == .success {}
    }

    private func reachFailed(_ why: String) {
        reachFailure = why
        if let board { central?.cancelPeripheralConnection(board) }
        board = nil
        request = nil
        answer = nil
        linked.signal()
    }

    private func linkDropped(_ why: String) {
        board = nil
        request = nil
        answer = nil
        exchangeFailure = why
        answered.signal()
    }

    // MARK: CBCentralManagerDelegate (on `queue`)

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        BridgeLogger.logRadio("anchor link: Bluetooth state \(central.state.rawValue)")
        radioKnown.signal()
        if central.state != .poweredOn, board != nil {
            linkDropped("Bluetooth went off")
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard board == nil else { return }
        BridgeLogger.logRadio("anchor link: found \(peripheral.identifier) at \(RSSI) dBm")
        board = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        BridgeLogger.logRadio("anchor link: connected to \(peripheral.identifier)")
        peripheral.discoverServices([AnchorLink.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        reachFailed("the board did not connect: \(error.map { "\($0)" } ?? "no reason given")")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        BridgeLogger.logRadio("anchor link: disconnected (\(error.map { "\($0)" } ?? "by the board"))")
        linkDropped("the board disconnected")
    }

    // MARK: CBPeripheralDelegate (on `queue`)

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == AnchorLink.serviceUUID }) else {
            reachFailed("the board has no DSM anchor service: \(error.map { "\($0)" } ?? "none found")")
            return
        }
        peripheral.discoverCharacteristics([AnchorLink.requestUUID, AnchorLink.answerUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        let found = service.characteristics ?? []
        guard error == nil,
              let request = found.first(where: { $0.uuid == AnchorLink.requestUUID }),
              let answer = found.first(where: { $0.uuid == AnchorLink.answerUUID }) else {
            reachFailed("the DSM anchor service lacks its request or answer characteristic: \(error.map { "\($0)" } ?? "")")
            return
        }
        self.request = request
        self.answer = answer
        peripheral.setNotifyValue(true, for: answer)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == AnchorLink.answerUUID else { return }
        guard error == nil, characteristic.isNotifying else {
            reachFailed("the board's answers could not be subscribed: \(error.map { "\($0)" } ?? "not notifying")")
            return
        }
        BridgeLogger.logRadio("anchor link: ready, one write carries \(peripheral.maximumWriteValueLength(for: .withoutResponse)) bytes")
        linked.signal()
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeReady.signal()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == AnchorLink.answerUUID else { return }
        if let error {
            linkDropped("a notification carried an error: \(error)")
            return
        }
        guard let data = characteristic.value, !data.isEmpty else { return }
        inbound.append(data)
        guard inbound.count >= 4 else { return }
        let length = Int(inbound[0]) | Int(inbound[1]) << 8 | Int(inbound[2]) << 16 | Int(inbound[3]) << 24
        if inbound.count >= 4 + length {
            answered.signal()
        }
    }
}
