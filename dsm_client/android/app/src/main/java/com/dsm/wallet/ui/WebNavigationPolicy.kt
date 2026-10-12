// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.ui

/** Where a navigation the page asks for may go. */
enum class WebNavigation {
    /** The app's own packaged page: it loads in the WebView. */
    App,

    /** The page's one link to the native QR scanner. */
    NativeQr,

    /** The release repository's new-issue form, opened in the system browser. */
    IssueForm,

    /** Anything else: never loaded in the WebView, never handed to another app. */
    Refused,
}

/**
 * The WebView's navigation policy (pre-audit item 13). The page is the app's
 * packaged origin and nothing else: it loads only its own assets, asks for the
 * native QR scanner by its one link, and sends the user to one outside page,
 * the beta bug and feedback form. Every other address is refused: another
 * site, the app's origin outside its assets, and every other scheme (`file:`,
 * `content:`, `intent:`, `javascript:`, `data:`, `http:`), so an injected link
 * can neither replace the page nor launch another app with the page's data.
 */
object WebNavigationPolicy {
    const val APP_ORIGIN = "https://appassets.androidplatform.net"
    private const val APP_HOST = "appassets.androidplatform.net"
    private const val APP_PATH_PREFIX = "/assets/"
    private const val ISSUE_FORM_HOST = "github.com"
    private const val ISSUE_FORM_PATH = "/deterministicstatemachine/dsm/issues/new"

    /** The navigation to `scheme://host/path`, as `android.net.Uri` splits it. */
    fun decide(scheme: String?, host: String?, path: String?): WebNavigation {
        val s = scheme?.lowercase()
        val h = host?.lowercase()
        return when {
            s == "https" && h == APP_HOST && path.orEmpty().startsWith(APP_PATH_PREFIX) ->
                WebNavigation.App
            s == "dsm" && h == "native" && path == "/qr/start" -> WebNavigation.NativeQr
            s == "https" && h == ISSUE_FORM_HOST && path == ISSUE_FORM_PATH -> WebNavigation.IssueForm
            else -> WebNavigation.Refused
        }
    }
}
