// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pre-audit item 13: the WebView loads only the app's own packaged page,
 * reaches the native QR scanner by its one link, and opens only the beta
 * issue form outside the app. Everything else is refused.
 */
class WebNavigationPolicyTest {
    private fun decide(scheme: String?, host: String?, path: String?) =
        WebNavigationPolicy.decide(scheme, host, path)

    @Test
    fun the_apps_own_page_loads_in_the_webview() {
        assertEquals(WebNavigation.App, decide("https", "appassets.androidplatform.net", "/assets/index.html"))
        assertEquals(WebNavigation.App, decide("HTTPS", "AppAssets.androidplatform.net", "/assets/js/main.js"))
    }

    @Test
    fun the_qr_link_and_the_issue_form_are_the_only_ways_out() {
        assertEquals(WebNavigation.NativeQr, decide("dsm", "native", "/qr/start"))
        assertEquals(
            WebNavigation.IssueForm,
            decide("https", "github.com", "/deterministicstatemachine/dsm/issues/new"),
        )
    }

    @Test
    fun every_other_address_is_refused() {
        val refused = listOf(
            Triple("https", "appassets.androidplatform.net", "/res/raw/secret"),
            Triple("http", "appassets.androidplatform.net", "/assets/index.html"),
            Triple("https", "evil.example", "/assets/index.html"),
            Triple("https", "github.com", "/deterministicstatemachine/dsm/issues"),
            Triple("https", "github.com", "/someone-else/dsm/issues/new"),
            Triple("https", "github.com.evil.example", "/deterministicstatemachine/dsm/issues/new"),
            Triple("http", "github.com", "/deterministicstatemachine/dsm/issues/new"),
            Triple("dsm", "native", "/wallet/send"),
            Triple("file", null, "/data/data/com.dsm.wallet/databases/dsm_client.db"),
            Triple("content", "com.dsm.wallet.provider", "/anything"),
            Triple("intent", null, null),
            Triple("javascript", null, null),
            Triple("data", null, null),
            Triple(null, null, null),
        )
        for ((scheme, host, path) in refused) {
            assertEquals("$scheme://$host$path", WebNavigation.Refused, decide(scheme, host, path))
        }
    }
}
