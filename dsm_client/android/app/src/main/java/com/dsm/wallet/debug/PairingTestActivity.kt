package com.dsm.wallet.debug

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import com.dsm.wallet.bridge.ble.BleCoordinator

class PairingTestActivity : AppCompatActivity() {
    private val tag = "PairingTestActivity"
    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Simple programmatic UI to avoid XML file changes
        val startAdvertBtn = Button(this).apply { text = "Start Advertise For Pairing" }
        val startScanBtn = Button(this).apply { text = "Start Scan For Pairing" }
        val stopAdvertBtn = Button(this).apply { text = "Stop Advertising" }
        val stopScanBtn = Button(this).apply { text = "Stop Scanning" }

        val layout = androidx.appcompat.widget.LinearLayoutCompat(this).apply {
            orientation = androidx.appcompat.widget.LinearLayoutCompat.VERTICAL
            addView(startAdvertBtn)
            addView(startScanBtn)
            addView(stopAdvertBtn)
            addView(stopScanBtn)
        }
        setContentView(layout)

        val bleService = BleCoordinator.getInstance(applicationContext)

        startAdvertBtn.setOnClickListener {
            Log.i(tag, "Requesting startAdvertising()")
            val ok = try { bleService.startAdvertising() } catch (t: Throwable) { Log.e(tag, "startAdvertising threw", t); false }
            Log.i(tag, "startAdvertising returned: $ok")
        }

        startScanBtn.setOnClickListener {
            Log.i(tag, "Requesting startScanning()")
            val ok = try { bleService.startScanning() } catch (t: Throwable) { Log.e(tag, "startScanning threw", t); false }
            Log.i(tag, "startScanning returned: $ok")
        }

        stopAdvertBtn.setOnClickListener {
            Log.i(tag, "Requesting stopAdvertising()")
            val ok = try { bleService.stopAdvertising() } catch (t: Throwable) { Log.e(tag, "stopAdvertising threw", t); false }
            Log.i(tag, "stopAdvertising returned: $ok")
        }

        stopScanBtn.setOnClickListener {
            Log.i(tag, "Requesting stopScanning()")
            val ok = try { bleService.stopScanning() } catch (t: Throwable) { Log.e(tag, "stopScanning threw", t); false }
            Log.i(tag, "stopScanning returned: $ok")
        }
    }
}
