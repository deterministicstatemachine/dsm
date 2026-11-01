// SPDX-License-Identifier: MIT OR Apache-2.0

import CoreBluetooth
import Foundation

/// The one entry to the radio (`BleCoordinator.kt`): the central it scans
/// and connects with, the GATT server it hosts, and one `PeerSession` per
/// address. It moves bytes on the link Rust names and nothing else (DSM
/// Amendment A27): Rust chooses the link, opens it, seals every byte on it,
/// and is told when it is gone; a vanished link fails closed and nothing
/// switches to another. Bluetooth runs while the app is open (owner,
/// 2026-11-01): the radio stops when the app leaves the foreground.
///
/// Every CoreBluetooth call runs on `queue`; Rust's callbacks arrive on
/// Rust's threads and hop onto it, blocking only where Android blocks (a
/// write answers once the stack took every record, or the link is gone).
final class BleCoordinator: NSObject, CBCentralManagerDelegate {
    static let shared = BleCoordinator()

    /// `write_on_link` answered that every record was written.
    static let writeSent: Int32 = 1
    /// `write_on_link` answered that the link is gone or refused a write.
    static let writeNotNow: Int32 = 0

    let queue = DispatchQueue(label: "com.dsm.wallet.ble")
    private let tag = "BleCoordinator"
    private var central: CBCentralManager?
    private lazy var server = GattServerHost(coordinator: self, queue: queue)
    private var peers: [String: PeerSession] = [:]
    private var clients: [String: GattClientSession] = [:]
    /// The contact the next DSM device the scan finds is connected for.
    private var pendingTarget: Data?

    // MARK: Facts, for the session

    var radioOn: Bool { central?.state == .poweredOn }
    var permitted: Bool { CBManager.authorization == .allowedAlways }
    var scanning: Bool { central?.isScanning ?? (central != nil) }
    var advertising: Bool { server.isAdvertising }

    /// Creating the managers asks the system for the Bluetooth permission.
    func promptForPermission() {
        queue.async { self.ensureManagers() }
    }

    private func ensureManagers() {
        let central = ensureCentral()
        let peripheral = server.ensureManager()
        DsmLog.info(tag, "managers present: central \(central.state.rawValue), peripheral \(peripheral.state.rawValue)")
    }

    /// Bring advertising in line with the identity, from Rust: the GATT
    /// server up and advertising on when there is one, advertising off when
    /// there is not. Idempotent.
    func refreshAdvertising() {
        queue.async {
            if DsmSdk.hasIdentity() {
                self.ensureManagers()
                let code = self.server.startAdvertising()
                DsmLog.info(self.tag, "refreshAdvertising: advertising requested (code \(code))")
            } else {
                self.server.stopAdvertising()
                DsmLog.info(self.tag, "refreshAdvertising: no local identity; not advertising")
            }
        }
    }

    /// The app left the foreground: the radio stops with it.
    func radioToBackground() {
        queue.async {
            if let central = self.central, central.isScanning {
                central.stopScan()
                self.postPageEvent(DsmSdk.bleRadioEvent(kind: 1, on: central.isScanning))
            }
            if self.server.isAdvertising {
                self.server.stopAdvertising()
                self.postPageEvent(DsmSdk.bleRadioEvent(kind: 2, on: self.server.isAdvertising))
            }
        }
    }

    // MARK: Host callbacks (Rust's threads)

    func startAdvertising() -> Int32 {
        queue.sync {
            guard DsmSdk.hasIdentity() else {
                DsmLog.warn(tag, "startAdvertising: refusing to advertise without a local identity")
                return 3
            }
            return server.startAdvertising()
        }
    }

    func startScanning() -> Int32 {
        queue.sync { startScanLocked() }
    }

    func stopScanning() -> Int32 {
        queue.sync {
            guard let central else { return 1 }
            let wasScanning = central.isScanning
            central.stopScan()
            if wasScanning { postPageEvent(DsmSdk.bleRadioEvent(kind: 1, on: central.isScanning)) }
            return 0
        }
    }

    /// Rust asks for a link to the contact `deviceId`: connect to the
    /// peripheral `addressHint` names when it is one this device knows and has
    /// no link to, else scan; the link that opens names `deviceId` as its
    /// handshake target.
    func requestConnect(deviceId: Data, addressHint: String) -> Int32 {
        queue.sync {
            let central = ensureCentral()
            // The reverse path: the contact may connect to this device instead.
            let advertising = server.startAdvertising()
            DsmLog.info(tag, "requestConnect: advertising for the reverse path (code \(advertising))")
            guard central.state == .poweredOn else {
                DsmLog.warn(tag, "requestConnect: the radio is not on")
                return 1
            }
            if let uuid = UUID(uuidString: addressHint),
               peers[addressHint]?.peripheral == nil,
               let known = central.retrievePeripherals(withIdentifiers: [uuid]).first {
                let peer = peer(addressHint)
                peer.target = deviceId
                connect(known, peer)
                return 0
            }
            pendingTarget = deviceId
            return startScanLocked()
        }
    }

    /// Write `records`, sealed by Rust, on exactly the link at `address`
    /// where this device is `role`. Blocks until the stack took every record
    /// or the link is gone. Nothing switches to another link.
    func writeOnLink(address: String, role: Int32, records: [Data]) -> Int32 {
        var found: PeerSession?
        queue.sync { found = peers[address] }
        guard let peer = found else { return BleCoordinator.writeNotNow }
        switch role {
        case BleConstants.linkRoleClient:
            return write(peer, records)
        case BleConstants.linkRoleServer:
            return server.notify(peer, records: records)
        default:
            DsmLog.error(tag, "writeOnLink: role \(role) names no link at \(address)")
            return -1
        }
    }

    // MARK: Peers (on `queue`)

    func peer(_ address: String) -> PeerSession {
        if let known = peers[address] { return known }
        let made = PeerSession(address: address)
        peers[address] = made
        return made
    }

    private func forget(_ peer: PeerSession) {
        if peer.isEmpty {
            peers.removeValue(forKey: peer.address)
            clients.removeValue(forKey: peer.address)
        }
    }

    private func ensureCentral() -> CBCentralManager {
        if let central { return central }
        let made = CBCentralManager(delegate: self, queue: queue)
        central = made
        return made
    }

    private func startScanLocked() -> Int32 {
        let central = ensureCentral()
        guard permitted else {
            postPageEvent(DsmSdk.blePermissionDeniedEvent(operation: "scan"))
            return 2
        }
        guard central.state == .poweredOn else {
            DsmLog.warn(tag, "startScanning: the radio is not on (\(central.state.rawValue))")
            return 1
        }
        if central.isScanning { return 0 }
        // Every DSM advertisement is wanted, with or without its service UUID:
        // an Android stack can truncate the UUID out and leave only the
        // manufacturer magic in the scan response, so the filter is applied
        // to what arrives rather than asked of the stack.
        central.scanForPeripherals(withServices: nil, options: nil)
        postPageEvent(DsmSdk.bleRadioEvent(kind: 1, on: central.isScanning))
        return central.isScanning ? 0 : 4
    }

    private func connect(_ peripheral: CBPeripheral, _ peer: PeerSession) {
        guard let central else { return }
        if central.isScanning {
            // A scan over a connect is a reliability hit on most stacks.
            central.stopScan()
            postPageEvent(DsmSdk.bleRadioEvent(kind: 1, on: central.isScanning))
        }
        peer.peripheral = peripheral
        clients[peer.address] = GattClientSession(coordinator: self, peer: peer, peripheral: peripheral)
        DsmLog.info(tag, "connecting to \(peer.address)")
        central.connect(peripheral, options: nil)
        queue.asyncAfter(deadline: .now() + BleConstants.connectionTimeout) { [weak self, weak peer] in
            guard let self, let peer, peer.clientLink == .closed, peer.peripheral?.state != .connected else { return }
            self.clientLinkFailed(peer, "not ready within \(BleConstants.connectionTimeout)")
        }
    }

    // MARK: Links, to and from Rust

    /// The client link is ready for its handshake: Rust opens it and hands
    /// back its first Hello, which is written on the link. Who answered is
    /// learned by the handshake.
    func openClientLink(_ peer: PeerSession) {
        let address = peer.address
        var target: Data?
        queue.sync { target = peer.target }
        peer.inbound.async { [self] in
            switch DsmSdk.bleLinkOpened(address: address, role: BleConstants.linkRoleClient, target: target) {
            case .reply(let hello):
                queue.sync { peer.clientLink = .opened }
                postPageEvent(DsmSdk.bleDeviceEvent(kind: 2, address: address, name: nil, rssi: 0))
                let written = write(peer, hello)
                DsmLog.info(tag, "link Hello to \(address) written=\(written)")
            case .refused(let why):
                DsmLog.warn(tag, "the link to \(address) was not opened: \(why)")
                queue.async { self.clientLinkFailed(peer, why) }
            }
        }
    }

    /// A central subscribed: Rust listens on this link (the server writes
    /// nothing first).
    func openServerLink(_ peer: PeerSession) {
        let address = peer.address
        peer.inbound.async { [self] in
            switch DsmSdk.bleLinkOpened(address: address, role: BleConstants.linkRoleServer, target: nil) {
            case .reply(let records):
                queue.sync { peer.serverLink = .opened }
                if !records.isEmpty {
                    let code = server.notify(peer, records: records)
                    DsmLog.info(tag, "the server link \(address) opened with \(records.count) records to write (code \(code))")
                }
            case .refused(let why):
                DsmLog.error(tag, "the link from \(address) was not opened: \(why)")
            }
        }
    }

    /// The central unsubscribed or disconnected: its link is closed in Rust too.
    func closeServerLink(_ peer: PeerSession) {
        let address = peer.address
        if peer.serverLink == .opened {
            peer.inbound.async {
                if let why = DsmSdk.bleLinkClosed(address: address, role: BleConstants.linkRoleServer) {
                    DsmLog.error(self.tag, "closing the link from \(address) failed: \(why)")
                }
            }
        }
        peer.clearServerState()
        forget(peer)
    }

    /// Bytes a peer wrote on the link: to Rust whole, off the radio's queue;
    /// what Rust answers goes back on the same link. Bytes Rust refused (a
    /// handshake that failed, a record that does not open) end the link: its
    /// next connection runs the handshake again.
    func inbound(_ peer: PeerSession, role: Int32, bytes: Data) {
        let address = peer.address
        peer.inbound.async { [self] in
            switch DsmSdk.bleInbound(address: address, role: role, bytes: bytes) {
            case .reply(let records):
                guard !records.isEmpty else { return }
                let code = role == BleConstants.linkRoleClient ? write(peer, records) : server.notify(peer, records: records)
                DsmLog.info(tag, "answer to \(address) (role \(role)): \(records.count) records, code \(code)")
            case .refused(let why):
                DsmLog.warn(tag, "the link at \(address) (role \(role)) refused its bytes: \(why)")
                queue.async {
                    if role == BleConstants.linkRoleClient {
                        self.clientLinkFailed(peer, why)
                    } else {
                        // A peripheral cannot drop a central; the link closes
                        // in Rust, and the central's next bytes find no session.
                        self.closeServerLink(peer)
                    }
                }
            }
        }
    }

    /// The client link failed at its connection, discovery, subscription or
    /// capacity step, or Rust refused its bytes: the connection is dropped,
    /// and the disconnect closes the link.
    func clientLinkFailed(_ peer: PeerSession, _ why: String) {
        DsmLog.warn(tag, "the link to \(peer.address) failed: \(why)")
        guard let peripheral = peer.peripheral else {
            peer.clearClientState()
            forget(peer)
            return
        }
        central?.cancelPeripheralConnection(peripheral)
    }

    /// The transport-level ACK after a window of notifications, written to
    /// TX_REQUEST: `0xFF ‖ b3 b2 b1 b0`.
    func writeChunkAck(_ peer: PeerSession, count: Int) {
        let value = UInt32(truncatingIfNeeded: count)
        let ack = Data([BleConstants.chunkAckMarker, UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
        guard let peripheral = peer.peripheral, let characteristic = peer.txRequest else { return }
        if peripheral.canSendWriteWithoutResponse {
            peripheral.writeValue(ack, for: characteristic, type: .withoutResponse)
        } else {
            DsmLog.warn(tag, "the chunk ACK for \(count) to \(peer.address) was not written: the stack is busy")
        }
    }

    /// Write records on the client link, in order, waiting for the stack
    /// between writes it refuses as busy. Blocks the caller until every
    /// record is taken or the link is gone.
    private func write(_ peer: PeerSession, _ records: [Data]) -> Int32 {
        enum Outcome { case taken, busy, gone }
        for record in records {
            var outcome = Outcome.busy
            while outcome == .busy {
                queue.sync {
                    guard let peripheral = peer.peripheral, peripheral.state == .connected, let characteristic = peer.txRequest else {
                        outcome = .gone
                        return
                    }
                    if peripheral.canSendWriteWithoutResponse {
                        peripheral.writeValue(record, for: characteristic, type: .withoutResponse)
                        outcome = .taken
                    }
                }
                if outcome == .busy, peer.writeReady.wait(timeout: .now() + BleConstants.readyTimeout) == .timedOut {
                    DsmLog.warn(tag, "write to \(peer.address): the stack stayed busy for \(BleConstants.readyTimeout)")
                    return BleCoordinator.writeNotNow
                }
            }
            if outcome == .gone { return BleCoordinator.writeNotNow }
        }
        return BleCoordinator.writeSent
    }

    // MARK: Radio state, from both managers

    func radioStateChanged() {
        DispatchQueue.main.async { SessionFacts.shared.publish("bluetoothState") }
    }

    /// Bluetooth went off: every link ended with the radio, and Rust is told
    /// of each one that was open.
    func radioOff() {
        for peer in Array(peers.values) {
            if peer.clientLink == .opened {
                let address = peer.address
                peer.inbound.async {
                    if let why = DsmSdk.bleLinkClosed(address: address, role: BleConstants.linkRoleClient) {
                        DsmLog.error(self.tag, "closing the link to \(address) failed: \(why)")
                    }
                }
            }
            peer.clearClientState()
            if peer.serverLink == .opened {
                closeServerLink(peer)
            } else {
                peer.clearServerState()
                forget(peer)
            }
        }
        pendingTarget = nil
    }

    func advertisingStarted() {
        postPageEvent(DsmSdk.bleRadioEvent(kind: 2, on: server.isAdvertising))
        radioStateChanged()
    }

    func advertisingFailed() {
        postPageEvent(DsmSdk.blePermissionDeniedEvent(operation: "advertise"))
        radioStateChanged()
    }

    func notifyReadyForAll() {
        for peer in peers.values { peer.notifyReady.signal() }
    }

    private func postPageEvent(_ envelope: Data) {
        guard !envelope.isEmpty else { return }
        EventRelay.shared.post(topic: "ble.envelope.bin", payload: envelope)
    }

    // MARK: CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        DsmLog.info(tag, "central manager state \(central.state.rawValue)")
        if central.state != .poweredOn {
            radioOff()
        }
        radioStateChanged()
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let services = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? []
        let overflow = advertisementData[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] ?? []
        let manufacturer = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data ?? Data()
        let magic = Data([UInt8(BleConstants.manufacturerId & 0xFF), UInt8(BleConstants.manufacturerId >> 8)]) + BleConstants.manufacturerMagic
        let isDsm = services.contains(BleConstants.serviceUUID)
            || overflow.contains(BleConstants.serviceUUID)
            || manufacturer.starts(with: magic)
        guard isDsm else { return }
        let address = peripheral.identifier.uuidString
        if let known = peers[address], known.peripheral != nil {
            return
        }
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? ""
        DsmLog.info(tag, "discovered DSM peer \(address) (rssi \(RSSI))")
        postPageEvent(DsmSdk.bleDeviceEvent(kind: 1, address: address, name: name, rssi: RSSI.int32Value))
        let peer = peer(address)
        // A contact Rust asked to reach with no address: this link's
        // handshake says Hello to it first.
        if let target = pendingTarget {
            peer.target = target
            pendingTarget = nil
        }
        connect(peripheral, peer)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        let address = peripheral.identifier.uuidString
        DsmLog.info(tag, "connected to \(address)")
        clients[address]?.discover(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let address = peripheral.identifier.uuidString
        DsmLog.warn(tag, "connection to \(address) failed: \(error.map { "\($0)" } ?? "no reason")")
        if let peer = peers[address] {
            peer.clearClientState()
            forget(peer)
        }
        postPageEvent(DsmSdk.bleDeviceEvent(kind: 3, address: address, name: nil, rssi: 0))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let address = peripheral.identifier.uuidString
        DsmLog.info(tag, "disconnected from \(address): \(error.map { "\($0)" } ?? "closed")")
        guard let peer = peers[address] else { return }
        if peer.clientLink == .opened {
            // A link Rust opened is closed in Rust too: its session is dropped,
            // and a contact it was paired with is reached for again while
            // frames are owed.
            peer.inbound.async {
                if let why = DsmSdk.bleLinkClosed(address: address, role: BleConstants.linkRoleClient) {
                    DsmLog.error(self.tag, "closing the link to \(address) failed: \(why)")
                }
            }
        }
        peer.clearClientState()
        forget(peer)
        postPageEvent(DsmSdk.bleDeviceEvent(kind: 3, address: address, name: nil, rssi: 0))
    }
}
