package com.dsm.wallet

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dsm.wallet.diagnostics.ArchitectureChecker

/**
 * Full-screen compatibility report for devices where native library failed to load.
 * Displays hardware details and allows user to screenshot for bug reporting.
 */
class IncompatibleDeviceScreen : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Gather hardware details
        val errorMessage = intent.getStringExtra("error_message") ?: "Unknown error"
        val compat = try {
            ArchitectureChecker.checkCompatibility()
        } catch (e: Throwable) {
            // Fallback if ArchitectureChecker itself is inaccessible
            ArchitectureChecker.ArchCompatibility(
                status = ArchitectureChecker.ArchStatus.UNKNOWN,
                deviceArch = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                supportedAbis = Build.SUPPORTED_ABIS.toList(),
                message = "Architecture check unavailable: ${e.message}",
                recommendation = "Please report this issue to the development team"
            )
        }
        
        // Build summary map for display
        val architectureSummary = buildMap<String, String> {
            put("Primary ABI", compat.deviceArch)
            put("All ABIs", compat.supportedAbis.joinToString(", "))
            put("Status", compat.status.name)
            put("Build.DEVICE", Build.DEVICE)
            put("Build.MODEL", Build.MODEL)
            put("Build.MANUFACTURER", Build.MANUFACTURER)
            put("Build.HARDWARE", Build.HARDWARE)
            put("Build.BOARD", Build.BOARD)
            put("Build.PRODUCT", Build.PRODUCT)
            put("OS.arch", System.getProperty("os.arch") ?: "unknown")
        }
        
        setContent {
            IncompatibleDeviceUI(
                errorMessage = errorMessage,
                compat = compat,
                architectureSummary = architectureSummary,
                onCopyDetails = { copyDetailsToClipboard(errorMessage, compat, architectureSummary) }
            )
        }
    }
    
    private fun copyDetailsToClipboard(
        errorMessage: String, 
        compat: ArchitectureChecker.ArchCompatibility,
        summary: Map<String, String>
    ) {
        val details = buildString {
            appendLine("DSM Compatibility Report")
            appendLine("=" .repeat(40))
            appendLine()
            appendLine("Error: $errorMessage")
            appendLine()
            appendLine("Compatibility Status:")
            appendLine("  Status: ${compat.status.name}")
            appendLine("  Message: ${compat.message}")
            if (compat.recommendation.isNotEmpty()) {
                appendLine("  Note: ${compat.recommendation}")
            }
            appendLine()
            appendLine("Device Hardware:")
            summary.forEach { (key, value) ->
                appendLine("  $key: $value")
            }
        }
        
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("DSM Compatibility Report", details)
        clipboard.setPrimaryClip(clip)
        
        Toast.makeText(this, "Compatibility report copied to clipboard", Toast.LENGTH_LONG).show()
    }
}

@Composable
fun IncompatibleDeviceUI(
    errorMessage: String,
    compat: ArchitectureChecker.ArchCompatibility,
    architectureSummary: Map<String, String>,
    onCopyDetails: () -> Unit
) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            background = Color(0xFF1a1a1a),
            surface = Color(0xFF2d2d2d),
            primary = Color(0xFFff6b6b),
            onBackground = Color(0xFFe0e0e0),
            onSurface = Color(0xFFe0e0e0)
        )
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp)
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Top
            ) {
                Spacer(modifier = Modifier.height(32.dp))
                
                // Title
                Text(
                    text = "Device Incompatible",
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Explanation
                Text(
                    text = "DSM cannot run on this device because the native cryptography library is incompatible with your CPU architecture.",
                    fontSize = 14.sp,
                    color = Color(0xFFcccccc),
                    lineHeight = 20.sp
                )
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Error details card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Error Details:",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFFffa500)
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = errorMessage,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFFcccccc),
                            lineHeight = 18.sp
                        )

                        if (compat.message.isNotBlank()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = compat.message,
                                fontSize = 12.sp,
                                color = Color(0xFFcccccc),
                                lineHeight = 18.sp
                            )
                        }

                        if (compat.recommendation.isNotBlank()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = compat.recommendation,
                                fontSize = 12.sp,
                                color = Color(0xFFffa500),
                                lineHeight = 18.sp
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Hardware details card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Device Hardware:",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFF4dd0e1)
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        architectureSummary.forEach { (key, value) ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                            ) {
                                Text(
                                    text = "$key:",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color(0xFFaaaaaa),
                                    modifier = Modifier.width(140.dp)
                                )
                                Text(
                                    text = value,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Color(0xFFe0e0e0)
                                )
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(32.dp))
                
                // Copy button
                Button(
                    onClick = onCopyDetails,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF4dd0e1),
                        contentColor = Color.Black
                    )
                ) {
                    Text(
                        text = "📋 COPY DETAILS FOR BUG REPORT",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Instructions
                Text(
                    text = "Tap the button above to copy device details, then screenshot this screen and send both to the development team.",
                    fontSize = 12.sp,
                    color = Color(0xFF888888),
                    lineHeight = 18.sp
                )
            }
        }
    }
}
