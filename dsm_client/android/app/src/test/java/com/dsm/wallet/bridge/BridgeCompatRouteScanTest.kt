package com.dsm.wallet.bridge

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Test

class BridgeCompatRouteScanTest {

    private val removedCompatRouteStrings = listOf(
        "identity.genesis.create",
        "device.qr.scan.start",
        "device.ble.scan.start",
        "device.ble.scan.stop",
        "device.ble.advertise.start",
        "device.ble.advertise.stop",
        "nfc.ring.stopRead",
    )

    private val removedBundleDispatchLiterals = listOf(
        "'identity.genesis.create'",
        "'device.qr.scan.start'",
        "'device.ble.scan.start'",
        "'device.ble.scan.stop'",
        "'device.ble.advertise.start'",
        "'device.ble.advertise.stop'",
        "'nfc.ring.stopRead'",
    )

    @Test
    fun bridgeRouterHandlerWasDeleted() {
        val repoRoot = findRepoRoot(Path.of("").toAbsolutePath())
        val handlerPath = repoRoot.resolve(
            "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeRouterHandler.kt"
        )
        assertFalse("Legacy BridgeRouterHandler should be deleted", Files.exists(handlerPath))
    }

    @Test
    fun singlePathBridgeDoesNotExposeRemovedCompatRoutes() {
        val source = readRepoFile(
            "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt"
        )

        val removedRoutes = removedCompatRouteStrings.map { "\"$it\" ->" } + listOf(
            "\"appRouterInvoke\" ->",
            "\"appRouterQuery\" ->",
            "\"createGenesisBin\" ->",
        )
        removedRoutes.forEach { marker ->
            assertFalse("Removed compat route is still present: $marker", source.contains(marker))
        }
    }

    @Test
    fun androidBundleDoesNotRetainRemovedCompatDispatchStrings() {
        val bundleSource = readAssetsJsBundle()

        removedBundleDispatchLiterals.forEach { marker ->
            assertFalse(
                "Android asset bundle still contains removed compat dispatch string: $marker",
                bundleSource.contains(marker)
            )
        }

        assertFalse(
            "Android asset bundle still contains bilateralOfflineSend compat dispatch",
            bundleSource.contains("methodName: 'bilateralOfflineSend'")
        )
        assertFalse(
            "Android asset bundle still contains legacy router transport RPC names",
            bundleSource.contains("'appRouterInvoke'") || bundleSource.contains("'appRouterQuery'")
        )
        assertFalse(
            "Android asset bundle still contains legacy bridge wrapper names",
            bundleSource.contains("appRouterInvokeBin") || bundleSource.contains("appRouterQueryBin")
        )
        assertFalse(
            "Android asset bundle still contains createGenesisBin alias",
            bundleSource.contains("createGenesisBin")
        )
    }

    private fun readRepoFile(relativePath: String): String {
        val repoRoot = findRepoRoot(Path.of("").toAbsolutePath())
        return String(Files.readAllBytes(repoRoot.resolve(relativePath)))
    }

    private fun readAssetsJsBundle(): String {
        val repoRoot = findRepoRoot(Path.of("").toAbsolutePath())
        val assetsDir = repoRoot.resolve("dsm_client/android/app/src/main/assets/js")
        require(Files.isDirectory(assetsDir)) { "Android assets JS directory missing: $assetsDir" }

        return Files.walk(assetsDir).use { paths ->
            paths
                .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".js") }
                .sorted()
                .map { String(Files.readAllBytes(it)) }
                .reduce("") { acc, file -> acc + "\n" + file }
        }
    }

    private tailrec fun findRepoRoot(start: Path): Path {
        if (Files.exists(start.resolve(".git"))) {
            return start
        }
        val parent = start.parent ?: error("Unable to locate repo root from $start")
        return findRepoRoot(parent)
    }
}
