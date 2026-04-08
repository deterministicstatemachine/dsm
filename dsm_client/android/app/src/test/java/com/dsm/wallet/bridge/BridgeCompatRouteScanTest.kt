package com.dsm.wallet.bridge

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Test

class BridgeCompatRouteScanTest {

    @Test
    fun bridgeRouterHandlerDoesNotRetainRemovedCompatRoutes() {
        val source = readRepoFile(
            "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeRouterHandler.kt"
        )

        val removedRoutes = listOf(
            "\"identity.genesis.create\" ->",
            "\"device.qr.scan.start\" ->",
            "\"device.ble.scan.start\" ->",
            "\"device.ble.scan.stop\" ->",
            "\"device.ble.advertise.start\" ->",
            "\"device.ble.advertise.stop\" ->",
            "\"nfc.ring.read\" ->",
            "\"nfc.ring.write\" ->",
            "\"nfc.ring.stopRead\" ->",
            "\"bilateralOfflineSend\" ->",
        )

        removedRoutes.forEach { marker ->
            assertFalse("Removed compat route is still present: $marker", source.contains(marker))
        }
    }

    @Test
    fun singlePathBridgeDoesNotExposeCreateGenesisBinRpc() {
        val source = readRepoFile(
            "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt"
        )

        assertFalse(
            "WebView bridge should not expose createGenesisBin anymore",
            source.contains("\"createGenesisBin\" ->")
        )
    }

    private fun readRepoFile(relativePath: String): String {
        val repoRoot = findRepoRoot(Path.of("").toAbsolutePath())
        return Files.readString(repoRoot.resolve(relativePath))
    }

    private tailrec fun findRepoRoot(start: Path): Path {
        if (Files.exists(start.resolve(".git"))) {
            return start
        }
        val parent = start.parent ?: error("Unable to locate repo root from $start")
        return findRepoRoot(parent)
    }
}
