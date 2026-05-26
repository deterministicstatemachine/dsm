package com.dsm.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SECURITY: WebView external-host allowlist lock.
 *
 * The first two tests freeze the allowlist contents byte-for-byte. Any
 * change to `WEBVIEW_ALLOWED_EXACT_HOSTS` or `WEBVIEW_ALLOWED_HOST_SUFFIXES`
 * in MainActivity.kt MUST be reflected in this file. That makes allowlist
 * expansion visible in PR review — the reviewer is forced to consciously
 * approve a new external host the WebView is allowed to fetch from.
 *
 * The third test asserts the predicate still correctly maps the sets to
 * accept/reject decisions for representative hosts.
 *
 * If you are editing this file because the allowlist legitimately grew,
 * please confirm:
 *   1. The new host is necessary for product behaviour (not dev convenience).
 *   2. The host operator's TLS/CORS posture has been reviewed.
 *   3. The PR description names the new host and the reason.
 */
class WebViewAllowlistTest {

    @Test
    fun allowlist_exact_hosts_frozen() {
        assertEquals(
            setOf(
                "tile.openstreetmap.org",
                "localhost",
                "127.0.0.1",
            ),
            WEBVIEW_ALLOWED_EXACT_HOSTS,
        )
    }

    @Test
    fun allowlist_host_suffixes_frozen() {
        assertEquals(
            setOf(
                ".tile.openstreetmap.org",
            ),
            WEBVIEW_ALLOWED_HOST_SUFFIXES,
        )
    }

    @Test
    fun isAllowlistedExternalHost_respects_sets() {
        // Exact-match accept.
        assertTrue(isAllowlistedExternalHost("tile.openstreetmap.org"))
        assertTrue(isAllowlistedExternalHost("localhost"))
        assertTrue(isAllowlistedExternalHost("127.0.0.1"))

        // Suffix-match accept (subdomains of openstreetmap tile servers).
        assertTrue(isAllowlistedExternalHost("a.tile.openstreetmap.org"))
        assertTrue(isAllowlistedExternalHost("b.tile.openstreetmap.org"))

        // Reject — not in either set.
        assertFalse(isAllowlistedExternalHost("evil.example.com"))
        assertFalse(isAllowlistedExternalHost("openstreetmap.org"))
        assertFalse(isAllowlistedExternalHost("tile.openstreetmap.org.attacker.com"))
        assertFalse(isAllowlistedExternalHost(""))
        assertFalse(isAllowlistedExternalHost("127.0.0.2"))
    }
}
