// SPDX-License-Identifier: MIT OR Apache-2.0
package com.dsm.wallet.ui

import android.content.Context
import android.text.InputType
import android.view.MotionEvent
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import android.webkit.WebView

/**
 * What the page asks the window to guard while it shows what it shows: the one byte of the
 * `setScreenGuards` bridge call. [SECRET]: a recovery phrase is on screen or being typed.
 * [CONFIRM]: an irreversible confirmation (a connect approval, a send) is on screen.
 */
@JvmInline
value class ScreenGuards(val bits: Int) {
    val secret: Boolean get() = (bits and SECRET) != 0
    val confirm: Boolean get() = (bits and CONFIRM) != 0

    companion object {
        const val SECRET = 1
        const val CONFIRM = 2
        val NONE = ScreenGuards(0)

        fun parse(payload: ByteArray): ScreenGuards {
            require(payload.size == 1) { "setScreenGuards: one byte of guards, not ${payload.size}" }
            val bits = payload[0].toInt() and 0xFF
            require((bits and (SECRET or CONFIRM).inv()) == 0) { "setScreenGuards: no guard has bits $bits" }
            return ScreenGuards(bits)
        }
    }
}

/**
 * The wallet's WebView, with what the page cannot do for itself.
 *
 * A touch that reaches it through another app's window drawn over it is dropped, as
 * `filterTouchesWhenObscured` drops it: an overlay cannot press the wallet's buttons for the user.
 *
 * While the page holds the [ScreenGuards.SECRET] guard (a recovery phrase on screen or typed), the
 * keyboard is told not to learn from what is typed and to offer no suggestions from it.
 */
class WalletWebView(context: Context) : WebView(context) {
    private var guards = ScreenGuards.NONE

    override fun onFilterTouchEventForSecurity(event: MotionEvent): Boolean =
        (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) == 0 && super.onFilterTouchEventForSecurity(event)

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        val connection = super.onCreateInputConnection(outAttrs)
        if (guards.secret) {
            outAttrs.imeOptions = outAttrs.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            outAttrs.inputType = (outAttrs.inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS) and
                InputType.TYPE_TEXT_FLAG_AUTO_CORRECT.inv()
        }
        return connection
    }

    /** Takes the page's guards; a keyboard already open is restarted so it reads them. */
    fun applyGuards(next: ScreenGuards) {
        val inputChanged = next.secret != guards.secret
        guards = next
        if (inputChanged) {
            context.getSystemService(InputMethodManager::class.java)?.restartInput(this)
        }
    }
}
