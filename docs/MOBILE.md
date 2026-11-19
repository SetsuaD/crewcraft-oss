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
| T403 | Device key in Android Keystore: a P-256 key generated inside the Keystore (hardware-backed where the phone has it), used for the enrollment request and for every TLS client signature through a custom rustls signer, so the private key never leaves the Keystore | an instrumented test on the emulator enrolls and signs in; the key's attestation says where it lives |
| T404 | App storage and lifecycle: the device record and last email in the app's private storage; reconnect after the app returns to the foreground | enroll, kill the app, reopen: it goes straight to sign-in |
| T405 | Invitation links open the app: an intent filter for `crewcraft://enroll` | tapping a link in a message opens the enrollment screen with the link filled in |
| T406 | Release packaging: a signed APK beside the desktop assets in the release, with `SHA256SUMS.txt`; a Play Store bundle (AAB) when the store listing exists | the APK installs on a real phone from the release page |
| T407 | Acceptance on a real phone (Android 10+): the two-person flow with a desktop on the other side | recorded in the release notes |

### How the Android app is built (T400, T401)

- `apps/crewcraft-android` is a library (`libcrewcraft_android.so`) that Android's own `android.app.NativeActivity`
  loads; the manifest names it in `android.app.lib_name` and sets `hasCode="false"`, so the APK has no
  `classes.dex`. `android-activity` (through winit and eframe) runs the app's `android_main` on its own thread, and
  that opens the same `DesktopApp` and `Window` as the desktop, with the bundled Inter font, rendered with OpenGL ES
  (glow). eframe's screen-reader support needs GameActivity (Java) on Android, so it is off there for now.
- The one exception to `unsafe_code = "forbid"`: android-activity finds the entry point by its symbol name, and
  `#[unsafe(no_mangle)] fn android_main` is unsafe code to the compiler. `apps/crewcraft-android` lowers the lint to
  `deny` and allows it on that one function only (`#[expect(unsafe_code)]` with the reason); everything else in the
  crate, and every other crate, stays `forbid`. No reviewed dependency exports that symbol for an app.
- The soft keyboard: winit asks for it when egui wants text input, and the app also asks explicitly
  (`show_soft_input`) when a text field gains the focus and hides it when none has the focus. On Android, typing
  arrives as key events that winit maps to characters, which egui turns into text.
- The app's data folder is `<internal data path>/crewcraft` (`/data/user/<user>/<package>/files/crewcraft`). Until
  T403 adds the Android Keystore there is no key store to seal the enrollment with, so the enrollment screen says the
  phone cannot keep an enrollment yet, as the desktop does on a computer without one.
- `cargo xtask apk` (docs/RELEASE.md) builds it. The APK zip, its alignment and its v2 signature are written in
  Rust; the NDK's clang links the library and `aapt2` compiles the manifest and icon (docs/NON-RUST-DEPENDENCIES.md).
- Known gaps for the next tasks: the window draws under the status bar and right up to the screen's edges (safe
  areas and margins with T402's layout and T404), and the keyboard covers the lower part of the window rather than
  resizing it (the composer above the keyboard is T402's).

## iOS (due 2027-03-31)

| Task | Piece | Status |
|---|---|---|
| T420 | Build lane on a Mac: `cargo xtask ios` builds `apps/crewcraft` for the iOS Simulator and writes `CrewCraft.app` in Rust (`xtask/src/ios.rs`): no Xcode project, asset catalog, storyboard, Swift or Objective-C. The device target (`aarch64-apple-ios`) waits for a signing identity (T424) | done for the simulator |
| T421 | The egui window on iOS (winit's iOS backend through eframe, wgpu on Metal), the bundled font and the phone layout, the on-screen keyboard for text fields, safe areas | done |
| T422 | Device key in the Secure Enclave (P-256, non-exportable), used for enrollment and TLS client signatures | |
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

## Prerequisites outside the code

- **Android SDK and NDK** on the Linux build machine (command-line tools, a platform, build-tools, NDK r27) and an
  emulator image for tests.
- **Signing identities.** A release APK and an AAB need an upload key; App Store builds need an Apple Developer
  identity. Which identity publishes the apps (and so whose name the stores show) is decided before T406 and T424.
- **Test devices:** an Android 10+ phone and an iPhone for T407 and T425.
