import re

with open('dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt', 'r') as f:
    content = f.read()

content = content.replace('if (peer.isConnected) { // Removed MTU > 23 restriction for robustness', 'if (peer.hasActiveClientSession) {')

with open('dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt', 'w') as f:
    f.write(content)
