# Phone apps: plan for milestone M6

Due dates: **Android 2027-02-28, iOS 2027-03-31** (ROADMAP.md). Both are the same Rust client the desktop runs: the
egui window (`crewcraft-desktop-ui`) over the shared client core, the connection worker, enrollment and the device
store, in a phone layout (REQUIREMENTS 2.9). No Kotlin, Java, Swift or Objective-C source (SPEC.md section 7):
platform features are reached from Rust.

"Working" for the dates means: install the app, enroll the phone from an invitation link, sign in with an
authenticator code, see your rooms, read and send messages, and come back to it after the app was closed, with the
device key held by the phone's hardware key store. Calls, files and push notifications come with M7 and M8.

## What carries over unchanged

The protocol, enrollment, the connection worker, the room list, composer and feed models, the invitation link and the
root-certificate check. The system test (T310) already proves them together; phones add a new shell, a new key store
and a new layout.

## Android (due 2027-02-28)

| Task | Piece | Proven by |
|---|---|---|
| T400 | Build lane: `cargo xtask apk` cross-compiles `aarch64-linux-android` (and `x86_64-linux-android` for the emulator) with the Android NDK and packages an APK around a `NativeActivity` (no Java), signed with a test key | **Done.** The APK installs on an emulator (Android 14, x86_64) and its log shows `crewcraft <version> (protocol <n>) on Android` |
| T401 | The egui window on Android through `eframe`'s Android support (`android-activity`), with the bundled font and the keyboard shown for text fields | **Done.** The enrollment screen renders on the emulator; tapping a field raises the soft keyboard and typing (on it, or with `adb shell input text`) reaches the field |
| T402 | Phone layout in `crewcraft-desktop-ui`: one pane at a time with back navigation, a bottom tab bar, larger touch targets, the composer above the keyboard | headless tests (egui_kittest) at phone sizes |
| T403 | Device key in Android Keystore: a P-256 key generated inside the Keystore (hardware-backed where the phone has it), used for the enrollment request and for every TLS client signature through a custom rustls signer, so the private key never leaves the Keystore | **Done.** The emulator self-test enrolls against a real server and signs in, then signs in again after a restart; the Keystore's `KeyInfo` says where the key lives (below) |
| T404 | App storage and lifecycle: the device record and last email in the app's private storage; reconnect after the app returns to the foreground | enroll, kill the app, reopen: it goes straight to sign-in |
| T405 | Invitation links open the app: an intent filter for `crewcraft://enroll` | **Done** for a link that starts the app: on the emulator, a link from a real server opened the enrollment screen with the link filled in, and enrolling went on to the server's authenticator setup. A link tapped while the app is already running brings it forward without filling the form (below) |
| T406 | Release packaging: a signed APK beside the desktop assets in the release, with `SHA256SUMS.txt`; a Play Store bundle (AAB) when the store listing exists | the APK installs on a real phone from the release page |
| T407 | Acceptance on a real phone (Android 10+): the two-person flow with a desktop on the other side | recorded in the release notes |

### How the Android app is built (T400, T401)

- `apps/crewcraft-android` is a library (`libcrewcraft_android.so`) that Android's own `android.app.NativeActivity`
  loads; the manifest names it in `android.app.lib_name` and sets `hasCode="false"`, so the APK has no
  `classes.dex`. `android-activity` (through winit and eframe) runs the app's `android_main` on its own thread, and
  that opens the same `DesktopApp` and `Window` as the desktop, with the bundled Inter font, rendered with OpenGL ES
  (glow). eframe's screen-reader support needs GameActivity (Java) on Android, so it is off there for now.
- The exceptions to `unsafe_code = "forbid"`, all in `apps/crewcraft-android`, which lowers the lint to `deny` and
  allows it on three functions only (`#[expect(unsafe_code)]` with the reason): android-activity finds the entry
  point by its symbol name, and `#[unsafe(no_mangle)] fn android_main` is unsafe code to the compiler; `java_vm`
  (T403) turns the JVM pointer android-activity records (in `ndk-context`) into a `jni::JavaVM` handle; and
  `activity` (T405) does the same for the activity pointer (`AndroidApp::activity_as_ptr`). Everything else in the
  crate, and every other crate, stays `forbid`. No reviewed dependency exports that symbol for an app.
- The soft keyboard: winit asks for it when egui wants text input, and the app also asks explicitly
  (`show_soft_input`) when a text field gains the focus and hides it when none has the focus. On Android, typing
  arrives as key events that winit maps to characters, which egui turns into text.
- The app's data folder is `<internal data path>/crewcraft` (`/data/user/<user>/<package>/files/crewcraft`). The
  device key lives in the Android Keystore (T403, below), and the record there only names it.
- `cargo xtask apk` (docs/RELEASE.md) builds it. The APK zip, its alignment and its v2 signature are written in
  Rust; the NDK's clang links the library and `aapt2` compiles the manifest and icon (docs/NON-RUST-DEPENDENCIES.md).
- Known gaps for the next tasks: the window draws under the status bar and right up to the screen's edges (safe
  areas and margins with T402's layout and T404), and the keyboard covers the lower part of the window rather than
  resizing it (the composer above the keyboard is T402's).

### The device key in the Android Keystore (T403)

- `crewcraft::hardware_key` is the platform-neutral half, shared with the iOS Secure Enclave (T422): a key store
  (`HardwareKeys`) makes, finds and deletes P-256 keys by alias, and adapters let such a key sign the certificate
  request (rcgen) and the TLS 1.3 client handshake (rustls, `ecdsa_secp256r1_sha256` only). The controller starts
  with `Controller::start_with_hardware_keys`; each enrollment makes a new key, `crewcraft-default-` and 16 random
  hex digits, and the device store keeps a version 3 record that names it (`DeviceStore::open_hardware`).
- `apps/crewcraft-android/src/keystore.rs` is the Android half, in Rust over JNI: `KeyPairGenerator("EC",
  "AndroidKeyStore")` with a `KeyGenParameterSpec` for signing with SHA-256 on `secp256r1`, in StrongBox first and
  otherwise in the trusted environment; `Signature("SHA256withECDSA")` to sign; `KeyInfo` to say where the key
  lives (security level on Android 12 and later, `isInsideSecureHardware` before).
- The emulator test: `cargo xtask apk --self-test` builds `selftest.rs` in place of the window, for a server named
  at build time. It joins from the invitation link, makes the key in the Keystore, enrolls, saves and reloads the
  record, and signs in over mutual TLS; started again, it signs in from the saved record. Run against a real
  `crewcraft-server` on the Android 14 emulator, see the T403 pull request for the log. The emulator's Keystore
  is software, so the hardware level is checked on a real phone with T407.

### Invitation links (T405)

- The manifest lets the activity open `crewcraft://enroll` links (`VIEW`, `DEFAULT`, `BROWSABLE`). At start the
  app reads the launching intent's data over JNI (`jvm::launch_link`, through `AndroidApp::activity_as_ptr`; the
  `ndk-context` context is the Application, not the activity), and `crewcraft::app::opened_with_link` takes it only
  if it parses as an invitation link. The window then fills the enrollment form's link field
  (`Update::InvitationLink`), only while the enrollment screen shows. The link is never logged.
- Known limit: the activity is `singleTask`, and `NativeActivity` gives native code no new-intent callback, so a
  link tapped while the app is already running brings it forward without filling the form; the person pastes it,
  or closes the app and taps the link again. Lifting this needs a Java `onNewIntent`, which the app does not have.

## iOS (due 2027-03-31)

| Task | Piece | Status |
|---|---|---|
| T420 | Build lane on a Mac: `cargo xtask ios` builds `apps/crewcraft` for the iOS Simulator and writes `CrewCraft.app` in Rust (`xtask/src/ios.rs`): no Xcode project, asset catalog, storyboard, Swift or Objective-C. The device target (`aarch64-apple-ios`) waits for a signing identity (T424) | done for the simulator |
| T421 | The egui window on iOS (winit's iOS backend through eframe, wgpu on Metal), the bundled font and the phone layout, the on-screen keyboard for text fields, safe areas | done |
| T422 | Device key in the Secure Enclave (P-256, non-exportable), used for enrollment and TLS client signatures | **Done.** The simulator self-test enrolls against a real server and signs in, then signs in again after a restart, with the key in the (simulated) Secure Enclave (below) |
| T423 | App storage, lifecycle, and `crewcraft://` links (a URL type) | |
| T424 | Distribution through TestFlight, then the App Store | |
| T425 | Acceptance on a real iPhone (iOS 17+) | |

### How the iOS app is put together (T420, T421)

`cargo xtask ios --version <v> --out <dir>` ([RELEASE.md](RELEASE.md#ios-simulator)) builds the same `crewcraft` program
as the desktop for `x86_64-apple-ios` or `aarch64-apple-ios-sim`, linked for iOS 17, and writes a flat `CrewCraft.app`:
the program, an `Info.plist` (identifier `io.github.setsuad.crewcraft`, `MinimumOSVersion` 17.0, an empty
`UILaunchScreen` so the app fills the screen, iPhone, portrait), the home-screen icons rendered from
`assets/icon/crewcraft.svg` and the license files, sealed ad hoc with `codesign --sign -`.

On iOS, `crewcraft` opens `DesktopApp` through `crewcraft::ios` (`apps/crewcraft/src/ios.rs`):

- **Window.** eframe runs winit's iOS backend, which starts UIKit's application loop from Rust's `main`. Only wgpu
  (Metal) is built for iOS; glow and the screen reader stay desktop-only (glutin has no iOS backend, and AccessKit has
  no iOS adapter yet).
- **Keyboard.** Tapping a text field gives it the focus; egui then asks for text input, and winit makes its view the
  first responder, which raises the keyboard; typed characters and Backspace arrive as key events. The enrollment and
  sign-in forms are as wide as the screen at most, so their fields always have a visible cursor (a field pushed past
  the screen's edges never asks for the keyboard).
- **Safe areas and the keyboard's frame.** `PhoneApp` reads the safe area and the keyboard layout guide of winit's
  view from UIKit (`objc2-ui-kit`, safe calls only) before every frame and lays the window out inside them, raising the
  bottom to the keyboard's top edge, so nothing sits under the status bar, the Dynamic Island, the home indicator or
  the keyboard.
- **GPU limits and the log.** The wgpu device is asked for exactly the limits the GPU offers (the simulator's Metal
  falls short of wgpu's defaults, and the window would not open). Warnings and errors from eframe, winit and wgpu go
  to standard error, which `xcrun simctl launch --console-pty` shows.
- **Data folder.** `Library/Application Support/CrewCraft` in the app's container (T423 decides what is kept there
  and whether it goes into device backups). Until T422 and T423 there is no key store on iOS, so the app shows its
  screens and says it cannot keep an enrollment yet.

Known gaps, each for a later task: the keyboard's Return key does nothing (winit 0.30 sends it as a `"\n"` character,
which egui does not treat as Enter; the forms' buttons and the composer's Send button work), there is no VoiceOver
yet, the app is iPhone-only and portrait-only, and it uses the app-delegate lifecycle that winit 0.30 has, not
UIScene. The App Store also needs a 1024-pixel icon in an asset catalog (T424).

**Checking it on a simulator.** Nothing can tap a simulator from a script, so `crewcraft --focus-first-field` (a
launch argument, `xcrun simctl launch <device> io.github.setsuad.crewcraft --focus-first-field`) gives the first text
field the focus and its cursor once the window is up, exactly as a tap would; the keyboard then comes up through the
same path. To try it by hand, open Simulator.app, turn off **I/O, Keyboard, Connect Hardware Keyboard** so the
on-screen keyboard shows, and tap a field.

### The device key in the Secure Enclave (T422)

- `crewcraft::ios_keys::IosKeychain` implements the same `HardwareKeys` as the Android Keystore (T403), over the safe
  `security-framework` crate (no unsafe code): `SecKey::new` with the Secure Enclave token makes a P-256 key, which is
  then added to the app's Keychain under its alias (`security-framework` makes generated keys permanent only on
  macOS, so on iOS the key is stored with `ItemAddOptions`; a Secure Enclave key may already be stored, which counts
  as success) and read back from it. Signing is `ECDSASignatureMessageX962SHA256`. The key's location is read from
  whether its private half can be exported: a Secure Enclave key cannot. Without a Secure Enclave the key is made in
  software and the log says so.
- The Keychain refuses an app without a Keychain access group (`errSecMissingEntitlement`, -34018). A simulator build
  carries one (`keychain-access-groups` naming the bundle) the way Xcode does for the simulator: linked into the
  program as its `__TEXT,__entitlements` section, with an ad-hoc signature that claims no entitlements (the simulator
  will not launch an ad-hoc app whose signature claims restricted ones). A device build gets its entitlements from
  its provisioning profile (T424).
- The simulator test: `cargo xtask ios --self-test` builds `crewcraft::selftest` (shared with Android) to run beside
  the window, for a server named at build time; its lines go to standard error. Run on an iPhone 17 simulator (iOS
  26.5) against a real `crewcraft-server` on the same Mac: it enrolled and signed in, then signed in again after a
  restart, with the key reported in `TrustedEnvironment`. The simulator's Secure Enclave is simulated, so the
  hardware is checked on a real iPhone with T425.
- `simctl launch --stdout/--stderr` needs absolute paths: with relative ones the launch is refused ("denied by service
  delegate").

## Prerequisites outside the code

- **Android SDK and NDK** on the Linux build machine (command-line tools, a platform, build-tools, NDK r27) and an
  emulator image for tests.
- **Signing identities.** A release APK and an AAB need an upload key; App Store builds need an Apple Developer
  identity. Which identity publishes the apps (and so whose name the stores show) is decided before T406 and T424.
- **Test devices:** an Android 10+ phone and an iPhone for T407 and T425.
