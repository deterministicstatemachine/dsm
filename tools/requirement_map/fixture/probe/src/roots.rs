// SPDX-License-Identifier: MIT OR Apache-2.0
//! Entry points: the JVM calls `JNI_OnLoad` and `JNI_OnUnload` by
//! specification; an export the Kotlin declares is a root, under the name it
//! is exported as; an export nothing declares is a dead-root candidate, and
//! what only it calls is not reached. An export the Kotlin declares under a
//! gate this map cannot decide may not be in the build: undecided, and so is
//! what only it calls. So is an export only a declaration this map cannot
//! spell could be (an `internal` member, whose JVM name carries its module).

use core::ffi::c_void;

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut c_void, reserved: *mut c_void) -> i32 {
    on_load(vm.is_null(), reserved.is_null())
}

fn on_load(no_vm: bool, no_reserved: bool) -> i32 {
    crate::installed::install();
    i32::from(no_vm) + i32::from(no_reserved) + 0x0001_0006
}

#[no_mangle]
pub extern "system" fn JNI_OnUnload(vm: *mut c_void, reserved: *mut c_void) {
    on_unload(vm, reserved);
}

fn on_unload(vm: *mut c_void, reserved: *mut c_void) {
    assert_eq!(vm.is_null(), reserved.is_null(), "the VM and its reserved word differ");
}

/// Exported as `Java_fixture_Probe_renamed`, which `Probe.renamed()` declares.
#[export_name = "Java_fixture_Probe_renamed"]
pub extern "system" fn exported_under_another_name() -> usize {
    renamed_helper()
}

fn renamed_helper() -> usize {
    50
}

/// Exported, and declared by no Kotlin.
#[no_mangle]
pub extern "system" fn Java_fixture_Probe_undeclared() -> usize {
    undeclared_helper()
}

fn undeclared_helper() -> usize {
    51
}

/// Declared by `Probe.gated()`, under a gate naming the pointer width.
#[cfg(any(feature = "leak", target_pointer_width = "64"))]
#[no_mangle]
pub extern "system" fn Java_fixture_Probe_gated() -> usize {
    gated_helper()
}

fn gated_helper() -> usize {
    54
}

/// What `Probe.hidden()`, an `internal` member, could be exported as.
#[no_mangle]
pub extern "system" fn Java_fixture_Probe_hidden_00024probe() -> usize {
    56
}
