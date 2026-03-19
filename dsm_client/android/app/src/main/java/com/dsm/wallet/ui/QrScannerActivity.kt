package com.dsm.wallet.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.util.Size
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Native QR scanner using Google ML Kit Barcode Scanning with CameraX.
 * 
 * Features:
 * - ML Kit for reliable QR decoding across all Android camera stacks (Samsung, etc.)
 * - CameraX ImageAnalysis at 1280x720 for optimal decode performance
 * - Tap-to-focus for manual focus override
 * - Torch toggle for low-light scanning
 * - Four-corner targeting overlay for alignment guidance
 * 
 * Result is returned via setResult() with:
 * - RESULT_OK + "qr_data" extra containing the raw QR string
 * - RESULT_CANCELED if user cancelled or error occurred
 */
class QrScannerActivity : AppCompatActivity() {
    
    companion object {
        const val TAG = "QrScanner"
        const val EXTRA_QR_DATA = "qr_data"
        const val REQUEST_CODE = 9001
        private const val CAMERA_PERMISSION_CODE = 1001
    }
    
    private lateinit var previewView: PreviewView
    private lateinit var overlayView: QrOverlayView
    private lateinit var torchButton: ImageButton
    private lateinit var cancelButton: ImageButton
    private lateinit var hintText: TextView
    
    private var camera: Camera? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private lateinit var cameraExecutor: ExecutorService
    private lateinit var barcodeScanner: BarcodeScanner
    
    private val scanLock = AtomicBoolean(false)
    private var torchEnabled = false
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "QrScannerActivity.onCreate")
        
        // Handle back press consistently
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                Log.i(TAG, "Back button pressed - cancelling scan")
                setResult(RESULT_CANCELED)
                finish()
            }
        })

        // Enable fullscreen immersive mode
        enableImmersiveMode()
        
        // Programmatic layout (avoids XML dependencies)
        val rootLayout = createLayout()
        setContentView(rootLayout)
        
        cameraExecutor = Executors.newSingleThreadExecutor()
        
        // Initialize ML Kit barcode scanner optimized for QR codes
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        barcodeScanner = BarcodeScanning.getClient(options)
        
        if (hasCameraPermission()) {
            startCamera()
        } else {
            requestCameraPermission()
        }
    }
    
    private fun enableImmersiveMode() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val controller = WindowCompat.getInsetsController(window, window.decorView)
        controller.hide(WindowInsetsCompat.Type.systemBars())
        controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
    }
    

    // onBackPressed is handled via OnBackPressedDispatcher (see onCreate)

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        Log.i(TAG, "onNewIntent: ignoring duplicate launch request")
    }
    
    @SuppressLint("ClickableViewAccessibility")
    private fun createLayout(): View {
        val root = FrameLayout(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(Color.BLACK)
        }
        
        // Camera preview
        previewView = PreviewView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
            implementationMode = PreviewView.ImplementationMode.PERFORMANCE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
        
        // Tap-to-focus handler
        previewView.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_UP) {
                focusOnPoint(event.x, event.y)
            }
            true
        }
        
        root.addView(previewView)
        
        // QR targeting overlay with four corners
        overlayView = QrOverlayView(this)
        root.addView(overlayView)
        
        // Top controls bar (cancel button)
        val topBar = LinearLayout(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.TOP
            }
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(16), dp(48), dp(16), dp(16))
        }
        
        cancelButton = ImageButton(this).apply {
            setBackgroundColor(Color.TRANSPARENT)
            setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
            setColorFilter(Color.WHITE)
            contentDescription = "Cancel"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
        }
        topBar.addView(cancelButton)
        
        // Spacer to push torch to right
        val spacer = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, 1, 1f)
        }
        topBar.addView(spacer)
        
        // Torch toggle button
        torchButton = ImageButton(this).apply {
            setBackgroundColor(Color.TRANSPARENT)
            setImageResource(android.R.drawable.ic_menu_view)
            setColorFilter(Color.WHITE)
            contentDescription = "Toggle flashlight"
            setOnClickListener { toggleTorch() }
        }
        topBar.addView(torchButton)
        
        root.addView(topBar)
        
        // Bottom hint text
        hintText = TextView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.BOTTOM
            }
            text = "Align QR code within the frame\nTap to focus • Flash button for low light"
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            textSize = 14f
            setPadding(dp(16), dp(16), dp(16), dp(80))
        }
        root.addView(hintText)
        
        return root
    }
    
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
    
    private fun hasCameraPermission(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == 
            PackageManager.PERMISSION_GRANTED
    }
    
    private fun requestCameraPermission() {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.CAMERA),
            CAMERA_PERMISSION_CODE
        )
    }
    
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startCamera()
            } else {
                Log.e(TAG, "Camera permission denied")
                setResult(RESULT_CANCELED, Intent().putExtra("error", "Camera permission denied"))
                finish()
            }
        }
    }
    
    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        
        cameraProviderFuture.addListener({
            cameraProvider = cameraProviderFuture.get()
            bindCameraUseCases()
        }, ContextCompat.getMainExecutor(this))
    }
    
    @SuppressLint("UnsafeOptInUsageError")
    private fun bindCameraUseCases() {
        val provider = cameraProvider ?: return
        
        // Unbind any existing use cases
        provider.unbindAll()
        
        // Camera selector - prefer back camera
        val cameraSelector = CameraSelector.Builder()
            .requireLensFacing(CameraSelector.LENS_FACING_BACK)
            .build()
        
        // Preview use case
        val preview = Preview.Builder()
            .build()
            .also {
                it.setSurfaceProvider(previewView.getSurfaceProvider())
            }
        
        // Image analysis at 1280x720 for optimal ML Kit decode performance
        // This is the key fix for "scanner sucks on some phones" - consistent frame resolution
        val imageAnalysis = ImageAnalysis.Builder()
            .setResolutionSelector(
                ResolutionSelector.Builder()
                    .setResolutionStrategy(
                        ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER)
                    )
                    .build()
            )
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
            .also {
                it.setAnalyzer(cameraExecutor) { imageProxy ->
                    processImage(imageProxy)
                }
            }
        
        try {
            // Bind to lifecycle
            camera = provider.bindToLifecycle(
                this,
                cameraSelector,
                preview,
                imageAnalysis
            )
            
            // Enable continuous autofocus
            setupAutoFocus()
            
            Log.i(TAG, "Camera bound successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to bind camera use cases", e)
            setResult(RESULT_CANCELED, Intent().putExtra("error", "Camera initialization failed"))
            finish()
        }
    }
    
    private fun setupAutoFocus() {
        camera?.cameraControl?.let { control ->
            // Trigger initial autofocus on center
            val meteringPointFactory = previewView.meteringPointFactory
            val centerPoint = meteringPointFactory.createPoint(0.5f, 0.5f)
            val focusAction = FocusMeteringAction.Builder(centerPoint)
                .setAutoCancelDuration(3, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            control.startFocusAndMetering(focusAction)
        }
    }
    
    private fun focusOnPoint(x: Float, y: Float) {
        camera?.cameraControl?.let { control ->
            val meteringPointFactory = previewView.meteringPointFactory
            val point = meteringPointFactory.createPoint(
                x / previewView.width,
                y / previewView.height
            )
            val focusAction = FocusMeteringAction.Builder(point)
                .setAutoCancelDuration(2, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            control.startFocusAndMetering(focusAction)
            Log.d(TAG, "Focus requested at ($x, $y)")
        }
    }
    
    private fun toggleTorch() {
        camera?.cameraControl?.let { control ->
            torchEnabled = !torchEnabled
            control.enableTorch(torchEnabled)
            torchButton.setColorFilter(if (torchEnabled) Color.YELLOW else Color.WHITE)
            Log.d(TAG, "Torch toggled: $torchEnabled")
        }
    }
    
    @SuppressLint("UnsafeOptInUsageError")
    private fun processImage(imageProxy: androidx.camera.core.ImageProxy) {
        // Skip if we've already found a result
        if (scanLock.get()) {
            imageProxy.close()
            return
        }
        
        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            imageProxy.close()
            return
        }
        
        val inputImage = InputImage.fromMediaImage(
            mediaImage,
            imageProxy.imageInfo.rotationDegrees
        )
        
        barcodeScanner.process(inputImage)
            .addOnSuccessListener { barcodes ->
                for (barcode in barcodes) {
                    val rawValue = barcode.rawValue
                    if (!rawValue.isNullOrBlank() && scanLock.compareAndSet(false, true)) {
                        Log.i(TAG, "QR code detected: ${rawValue.take(100)}...")
                        onQrCodeDetected(rawValue)
                        break
                    }
                }
            }
            .addOnFailureListener { e ->
                Log.w(TAG, "Barcode scan failed", e)
            }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }
    
    private fun onQrCodeDetected(data: String) {
        runOnUiThread {
            hintText.text = "QR Code detected!"
            
            // Small delay to show feedback, then return result
            previewView.postDelayed({
                val resultIntent = Intent().apply {
                    putExtra(EXTRA_QR_DATA, data)
                }
                setResult(RESULT_OK, resultIntent)
                finish()
            }, 200)
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
        barcodeScanner.close()
        cameraProvider?.unbindAll()
        Log.i(TAG, "QrScannerActivity.onDestroy")
    }
}

/**
 * Custom view that draws a four-corner targeting frame overlay.
 */
class QrOverlayView(context: android.content.Context) : View(context) {
    
    private val cornerPaint = android.graphics.Paint().apply {
        color = Color.parseColor("#6ba94d") // DSM green
        strokeWidth = 8f
        style = android.graphics.Paint.Style.STROKE
        isAntiAlias = true
    }
    
    private val dimPaint = android.graphics.Paint().apply {
        color = Color.parseColor("#66000000") // Semi-transparent black
        style = android.graphics.Paint.Style.FILL
    }
    
    init {
        layoutParams = FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        )
    }
    
    override fun onDraw(canvas: android.graphics.Canvas) {
        super.onDraw(canvas)
        
        val w = width.toFloat()
        val h = height.toFloat()
        
        // Calculate QR target box (centered, 80% of min dimension)
        val boxSize = minOf(w, h) * 0.75f
        val left = (w - boxSize) / 2
        val top = (h - boxSize) / 2
        val right = left + boxSize
        val bottom = top + boxSize
        
        // Draw semi-transparent overlay outside the box
        // Top region
        canvas.drawRect(0f, 0f, w, top, dimPaint)
        // Bottom region
        canvas.drawRect(0f, bottom, w, h, dimPaint)
        // Left region
        canvas.drawRect(0f, top, left, bottom, dimPaint)
        // Right region
        canvas.drawRect(right, top, w, bottom, dimPaint)
        
        // Draw four corner brackets
        val cornerLength = boxSize * 0.15f
        
        // Top-left corner
        canvas.drawLine(left, top + cornerLength, left, top, cornerPaint)
        canvas.drawLine(left, top, left + cornerLength, top, cornerPaint)
        
        // Top-right corner
        canvas.drawLine(right - cornerLength, top, right, top, cornerPaint)
        canvas.drawLine(right, top, right, top + cornerLength, cornerPaint)
        
        // Bottom-left corner
        canvas.drawLine(left, bottom - cornerLength, left, bottom, cornerPaint)
        canvas.drawLine(left, bottom, left + cornerLength, bottom, cornerPaint)
        
        // Bottom-right corner
        canvas.drawLine(right - cornerLength, bottom, right, bottom, cornerPaint)
        canvas.drawLine(right, bottom - cornerLength, right, bottom, cornerPaint)
    }
}
