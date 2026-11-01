// SPDX-License-Identifier: MIT OR Apache-2.0

import CoreBluetooth
import Foundation

/// One GATT client link: this device connected to a peer's DSM service and
/// moves bytes on it. It discovers the service, subscribes to TX_RESPONSE,
/// measures what one write can carry, and only then lets Rust open the link;
/// a link that cannot carry one sealed record is not a route and is dropped.
/// What arrives on TX_RESPONSE goes to Rust whole; what Rust answers is
/// written back on TX_REQUEST. Nothing here reads a byte of either.
final class GattClientSession: NSObject, CBPeripheralDelegate {
    private unowned let coordinator: BleCoordinator
    private let peer: PeerSession
    private let tag = "GattClientSession"

    init(coordinator: BleCoordinator, peer: PeerSession, peripheral: CBPeripheral) {
        self.coordinator = coordinator
        self.peer = peer
        super.init()
        peripheral.delegate = self
    }

    /// Service discovery, once the link is connected.
    func discover(_ peripheral: CBPeripheral) {
        peripheral.discoverServices([BleConstants.serviceUUID])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == BleConstants.serviceUUID }) else {
            coordinator.clientLinkFailed(peer, "service discovery found no DSM service: \(error.map { "\($0)" } ?? "none advertised")")
            return
        }
        peripheral.discoverCharacteristics([BleConstants.txRequestUUID, BleConstants.txResponseUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        let request = service.characteristics?.first { $0.uuid == BleConstants.txRequestUUID }
        let response = service.characteristics?.first { $0.uuid == BleConstants.txResponseUUID }
        guard error == nil, let request, let response else {
            coordinator.clientLinkFailed(peer, "the DSM service lacks TX_REQUEST or TX_RESPONSE: \(error.map { "\($0)" } ?? "")")
            return
        }
        peer.txRequest = request
        peer.txResponse = response
        // TX_RESPONSE must be subscribed before the handshake: the peer's
        // answers come back on it.
        peripheral.setNotifyValue(true, for: response)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == BleConstants.txResponseUUID else { return }
        guard error == nil, characteristic.isNotifying else {
            coordinator.clientLinkFailed(peer, "TX_RESPONSE subscription failed: \(error.map { "\($0)" } ?? "not notifying")")
            return
        }
        // iOS asks for no MTU; the link's write capacity is what it measures.
        // A link that cannot carry one sealed record in one write does not
        // become a route (fail closed).
        let capacity = peripheral.maximumWriteValueLength(for: .withoutResponse)
        guard capacity >= BleConstants.minWriteValueLength else {
            coordinator.clientLinkFailed(peer, "one write carries \(capacity) bytes; a sealed record needs \(BleConstants.minWriteValueLength)")
            return
        }
        DsmLog.info(tag, "\(peer.address): TX_RESPONSE subscribed, write capacity \(capacity) bytes")
        coordinator.openClientLink(peer)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == BleConstants.txResponseUUID, let data = characteristic.value, !data.isEmpty else { return }
        if let error {
            DsmLog.warn(tag, "\(peer.address): a notification carried an error: \(error)")
            return
        }
        // The server prepends `0xFF ‖ nonce` to the first notification of each
        // transfer; a new nonce resets the ACK count. 0xFF begins no radio byte
        // Rust takes (0x05 handshake, 0x06 record), so it marks the header alone.
        var payload = data
        if data.count > 2, data[data.startIndex] == BleConstants.chunkAckMarker {
            let nonce = data[data.startIndex + 1]
            if peer.currentTransferNonce != nonce || peer.notificationCount > 0 {
                DsmLog.info(tag, "\(peer.address): transfer nonce \(nonce) (count was \(peer.notificationCount))")
            }
            peer.currentTransferNonce = nonce
            peer.notificationCount = 0
            payload = data.dropFirst(BleConstants.transferHeader)
        }
        peer.notificationCount += 1
        if peer.notificationCount % BleConstants.notificationWindow == 0 {
            coordinator.writeChunkAck(peer, count: peer.notificationCount)
        }
        coordinator.inbound(peer, role: BleConstants.linkRoleClient, bytes: Data(payload))
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        peer.writeReady.signal()
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        if invalidatedServices.contains(where: { $0.uuid == BleConstants.serviceUUID }) {
            coordinator.clientLinkFailed(peer, "the peer's DSM service was invalidated")
        }
    }
}
