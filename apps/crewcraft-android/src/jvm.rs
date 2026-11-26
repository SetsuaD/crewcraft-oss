//! The app's handles on the Java side: the JVM (for the Android Keystore, T403) and the activity that started it
//! (for the link it was opened with, T405). android-activity records the JVM in `ndk-context` (whose "context" is the
//! Application, not the activity) and hands out the activity through `AndroidApp::activity_as_ptr`; turning those
//! raw pointers into `jni` handles is the crate's unsafe code besides `android_main` itself.
//!
//! Owns: those two conversions, and reading the launch intent's data. Called by: `keystore`, `shell`. Calls: the
//! JVM through the `jni` crate.

#[cfg(not(feature = "selftest"))]
use std::ffi::c_void;

use jni::JavaVM;
#[cfg(not(feature = "selftest"))]
use jni::objects::{JObject, JString};
#[cfg(not(feature = "selftest"))]
use jni::{Env, jni_sig, jni_str};

/// The process's JVM, or `None` if android-activity recorded none.
#[expect(unsafe_code, reason = "the JVM pointer comes from ndk-context, which android-activity sets before android_main runs")]
pub fn java_vm() -> Option<JavaVM> {
    let vm = ndk_context::android_context().vm();
    if vm.is_null() {
        return None;
    }
    // SAFETY: `vm` is the process's `JavaVM*`, valid for the life of the process; android-activity recorded it in
    // ndk-context when the activity was created, before calling `android_main`.
    Some(unsafe { JavaVM::from_raw(vm.cast()) })
}

/// `activity` (from `AndroidApp::activity_as_ptr`) as a handle in `env`, or `None` if it is null. The self-test build
/// does not read the launch link, so it leaves this out.
#[cfg(not(feature = "selftest"))]
#[expect(unsafe_code, reason = "the activity reference comes from android-activity's AndroidApp::activity_as_ptr")]
fn activity<'local>(env: &Env<'local>, activity: *mut c_void) -> Option<JObject<'local>> {
    if activity.is_null() {
        return None;
    }
    // SAFETY: `activity` is the JNI global reference to the running `NativeActivity` that android-activity holds for
    // the life of the activity (`ANativeActivity::clazz`). A `JObject` made from it is not deleted when dropped.
    Some(unsafe { JObject::from_raw(env, activity.cast()) })
}

/// The data of the intent that started the activity (`getIntent().getDataString()`): the link when the app was
/// opened from a `crewcraft://` link, otherwise `None`.
#[cfg(not(feature = "selftest"))]
pub fn launch_link(vm: &JavaVM, activity_ptr: *mut c_void) -> Option<String> {
    let read = vm.attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
        let Some(activity) = activity(env, activity_ptr) else {
            log::warn!("CrewCraft: no activity handle, so the launch link cannot be read");
            return Ok(None);
        };
        let intent = env.call_method(&activity, jni_str!("getIntent"), jni_sig!("()Landroid/content/Intent;"), &[])?.l()?;
        if intent.is_null() {
            return Ok(None);
        }
        let data = env.call_method(&intent, jni_str!("getDataString"), jni_sig!("()Ljava/lang/String;"), &[])?.l()?;
        if data.is_null() {
            return Ok(None);
        }
        let data = env.cast_local::<JString>(data)?;
        data.try_to_string(env).map(Some)
    });
    // The error names a JNI failure or a Java exception class, never the link.
    read.unwrap_or_else(|error| {
        log::warn!("CrewCraft could not read the launch link: {error}");
        None
    })
}
