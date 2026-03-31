# ─────────────────────────────────────────────────────────
# Keep native methods (unified JNI only)
-keepclasseswithmembers class * { native <methods>; }

# No legacy JS bridges; events are delivered via MCP envelope through SinglePathWebViewBridge

# Preserve any other @JavascriptInterface methods
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Preserve all Protobuf-generated message classes
-keep class dsm.** { *; }
-keepclassmembers class dsm.** { *; }

# Keep the Protobuf runtime (lite)
-keep class com.google.protobuf.** { *; }

# Keep Kotlin metadata (needed for builders & DSL)
-keep class kotlin.Metadata { *; }

# Preserve required attributes for Protobuf & JNI
-keepattributes Signature, *Annotation*, EnclosingMethod, InnerClasses, SourceFile, LineNumberTable

# Keep all app classes — JNI, bridge, BLE, and contacts use reflection/native calls
# that R8 cannot trace. Stripping these causes runtime crashes in release builds.
-keep class com.dsm.wallet.** { *; }
-keep class com.dsm.native.** { *; }

# ─────────────────────────────────────────────────────────