// path: dsm_client/deterministic_state_machine/dsm_sdk/src/jni/common.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! JNI common utilities (production-safe, protobuf-only, no JSON/base64/hex)

use jni::{
    objects::{GlobalRef, JByteArray, JClass, JObject, JValueOwned},
    sys::jbyteArray,
    JNIEnv, JavaVM,
};
use std::sync::OnceLock;

/// Single, process-lifetime JavaVM handle (installed from `JNI_OnLoad`)
pub static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Cached app ClassLoader - used by worker threads that attach via attach_current_thread().
/// When native threads attach to JVM, they get the system classloader which can't find
/// app classes like `com.dsm.wallet.bridge.SinglePathWebViewBridge`.
/// This GlobalRef to the app's ClassLoader is captured from the main thread.
static APP_CLASS_LOADER: OnceLock<GlobalRef> = OnceLock::new();

/// Store the JavaVM pointer (call from your `JNI_OnLoad`)
pub fn set_java_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
}

/// Store the app's ClassLoader (call from main thread during init)
pub fn set_app_class_loader(loader: GlobalRef) {
    let _ = APP_CLASS_LOADER.set(loader);
}

/// Get the cached app ClassLoader
pub fn get_app_class_loader() -> Option<&'static GlobalRef> {
    APP_CLASS_LOADER.get()
}

/// Initialize the app ClassLoader from the current thread's context classloader.
/// This MUST be called from the main thread (or any thread with the app's classloader).
/// Call this early during JNI initialization (e.g., in JNI_OnLoad or first bridge call).
pub fn init_app_class_loader_from_current_thread(env: &mut JNIEnv<'_>) -> Result<(), String> {
    if APP_CLASS_LOADER.get().is_some() {
        // Already initialized
        return Ok(());
    }

    // Get current thread's ClassLoader via: Thread.currentThread().getContextClassLoader()
    let thread_class = env
        .find_class("java/lang/Thread")
        .map_err(|e| format!("find_class Thread failed: {e}"))?;

    let current_thread = env
        .call_static_method(thread_class, "currentThread", "()Ljava/lang/Thread;", &[])
        .map_err(|e| format!("currentThread() failed: {e}"))?
        .l()
        .map_err(|e| format!("currentThread l() failed: {e}"))?;

    let class_loader = env
        .call_method(
            &current_thread,
            "getContextClassLoader",
            "()Ljava/lang/ClassLoader;",
            &[],
        )
        .map_err(|e| format!("getContextClassLoader() failed: {e}"))?
        .l()
        .map_err(|e| format!("getContextClassLoader l() failed: {e}"))?;

    if class_loader.is_null() {
        return Err("Context ClassLoader is null".to_string());
    }

    let global_ref = env
        .new_global_ref(class_loader)
        .map_err(|e| format!("new_global_ref failed: {e}"))?;

    set_app_class_loader(global_ref);
    log::info!("[JNI] App ClassLoader cached successfully");
    Ok(())
}

/// Find a class using the app's cached ClassLoader (works from worker threads).
/// Falls back to env.find_class if no cached classloader (may fail on worker threads).
pub fn find_class_with_app_loader<'a>(
    env: &mut JNIEnv<'a>,
    class_name: &str,
) -> Result<JClass<'a>, String> {
    // Try using cached app classloader first (needed for worker threads)
    if let Some(loader) = APP_CLASS_LOADER.get() {
        // Convert class name: "com/dsm/wallet/Foo" -> "com.dsm.wallet.Foo"
        let java_class_name = class_name.replace('/', ".");
        let j_class_name = env
            .new_string(&java_class_name)
            .map_err(|e| format!("new_string failed: {e}"))?;

        // Call: loader.loadClass(className)
        let class_obj = env
            .call_method(
                loader.as_obj(),
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[jni::objects::JValue::Object(&j_class_name)],
            )
            .map_err(|e| format!("loadClass({}) failed: {e}", java_class_name))?
            .l()
            .map_err(|e| format!("loadClass l() failed: {e}"))?;

        // Safety: JObject -> JClass cast is valid because loadClass returns Class<?>
        Ok(unsafe { JClass::from_raw(class_obj.into_raw()) })
    } else {
        // Use standard find_class (works on main thread, fails on worker threads)
        env.find_class(class_name)
            .map_err(|e| format!("find_class({}) failed: {e}", class_name))
    }
}

/// Get raw JavaVM pointer (use only if a C interface demands it)
pub fn get_java_vm_ptr() -> Option<*mut jni::sys::JavaVM> {
    JAVA_VM.get().map(|vm| vm.get_java_vm_pointer())
}

/// Get a borrowed JavaVM handle (preferred)
pub fn get_java_vm_borrowed() -> Option<&'static JavaVM> {
    JAVA_VM.get()
}

/// Get a temporary JavaVM value handle (compatible with existing call sites)
///
/// Safety note: `JavaVM` in the `jni` crate is a lightweight handle wrapper and
/// does not own/destroy the VM on drop. Re-wrapping from a raw pointer here is
/// safe as long as the VM outlives the process (which it does).
pub fn get_java_vm() -> Option<JavaVM> {
    get_java_vm_ptr().and_then(|ptr| unsafe { JavaVM::from_raw(ptr).ok() })
}

/// Run a closure with an attached `JNIEnv` for the current thread.
///
/// - Uses `get_env()` when already attached; otherwise attaches the thread
///   (detaches automatically via `AttachGuard` drop).
/// - Accepts a borrowed `&JNIEnv` to work with both `JNIEnv` and `AttachGuard`.
pub fn with_env<F, T>(f: F) -> Result<T, String>
where
    for<'a> F: FnOnce(&'a JNIEnv<'a>) -> Result<T, String>,
{
    let vm = get_java_vm_borrowed().ok_or("JavaVM not set")?;

    match vm.get_env() {
        Ok(env) => f(&env),
        Err(_) => {
            let env = vm
                .attach_current_thread()
                .map_err(|e| format!("attach_current_thread failed: {e}"))?;
            // `AttachGuard` derefs to `JNIEnv`, so `&env` coerces to `&JNIEnv`.
            f(&env)
        }
    }
}

/// Convert Rust bytes → Java `byte[]` (no extra encodings)
pub fn bytes_to_jbytearray(env: &JNIEnv<'_>, bytes: &[u8]) -> Result<jbyteArray, String> {
    env.byte_array_from_slice(bytes)
        .map(|a| a.into_raw())
        .map_err(|e| format!("new byte[] failed: {e}"))
}

/// Convert Java `byte[]` → `Vec<u8>` (no extra encodings)
pub fn jbytearray_to_vec(env: &JNIEnv<'_>, array: JByteArray<'_>) -> Result<Vec<u8>, String> {
    env.convert_byte_array(array)
        .map_err(|e| format!("convert byte[] failed: {e}"))
}

/// Convenience: read an optional `byte[]` method result (returns empty on null)
pub fn jvalue_bytearray_to_vec(env: &JNIEnv<'_>, val: JValueOwned) -> Result<Vec<u8>, String> {
    // `.l()` CONSUMES `val`; call it exactly once.
    let obj: JObject = match val.l() {
        Ok(o) => o,
        Err(_) => return Ok(Vec::new()),
    };
    if obj.is_null() {
        return Ok(Vec::new());
    }
    let jba = JByteArray::from(obj);
    jbytearray_to_vec(env, jba)
}
