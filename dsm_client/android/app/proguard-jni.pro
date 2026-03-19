# ─────────────────────────────────────────────────────────
# No legacy DsmNative; keep native methods in unified JNI only

# No legacy JS bridges; SinglePathWebViewBridge enforces MCP-only path

# Preserve any other @JavascriptInterface entry in your app
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Preserve Protobuf-generated classes (for reflection & lite)
-keep class dsm.** { *; }
-keepclassmembers class dsm.** { *; }

# Keep Protobuf runtime APIs
-keep class com.google.protobuf.** { *; }

# Keep Kotlin metadata (for your builders & DSL)
-keep class kotlin.Metadata { *; }

# Preserve method signatures & annotations needed by Protobuf & JNI
-keepattributes Signature, *Annotation*, EnclosingMethod, InnerClasses, SourceFile, LineNumberTable

# No other keep rules are required—everything else can be minified.
# ─────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────