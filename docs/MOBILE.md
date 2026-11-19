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
| T400 | Build lane: `cargo xtask apk` cross-compiles `aarch64-linux-android` (and `x86_64-linux-android` for the emulator) with the Android NDK and packages an APK around a `NativeActivity` (no Java), signed with a test key | the APK installs on an emulator and `crewcraft --version`'s equivalent appears in its log |
| T401 | The egui window on Android through `eframe`'s Android support (`android-activity`), with the bundled font and the keyboard shown for text fields | the enrollment screen renders on the emulator; typing reaches the field |
| T402 | Phone layout in `crewcraft-desktop-ui`: one pane at a time with back navigation, a bottom tab bar, larger touch targets, the composer above the keyboard | headless tests (egui_kittest) at phone sizes |
| T403 | Device key in Android Keystore: a P-256 key generated inside the Keystore (hardware-backed where the phone has it), used for the enrollment request and for every TLS client signature through a custom rustls signer, so the private key never leaves the Keystore | an instrumented test on the emulator enrolls and signs in; the key's attestation says where it lives |
| T404 | App storage and lifecycle: the device record and last email in the app's private storage; reconnect after the app returns to the foreground | enroll, kill the app, reopen: it goes straight to sign-in |
| T405 | Invitation links open the app: an intent filter for `crewcraft://enroll` | tapping a link in a message opens the enrollment screen with the link filled in |
| T406 | Release packaging: a signed APK beside the desktop assets in the release, with `SHA256SUMS.txt`; a Play Store bundle (AAB) when the store listing exists | the APK installs on a real phone from the release page |
| T407 | Acceptance on a real phone (Android 10+): the two-person flow with a desktop on the other side | recorded in the release notes |

## iOS (due 2027-03-31)

| Task | Piece |
|---|---|
| T420 | Build lane on a Mac: `aarch64-apple-ios` (and the simulator targets), an Xcode-free app bundle where possible, otherwise a minimal generated Xcode project with no Swift source |
| T421 | The egui window on iOS (winit's iOS backend), keyboard handling, safe areas |
| T422 | Device key in the Secure Enclave (P-256, non-exportable), used for enrollment and TLS client signatures |
| T423 | App storage, lifecycle, and `crewcraft://` links (a URL type) |
| T424 | Distribution through TestFlight, then the App Store |
| T425 | Acceptance on a real iPhone (iOS 17+) |

## Prerequisites outside the code

- **Android SDK and NDK** on the Linux build machine (command-line tools, a platform, build-tools, NDK r27) and an
  emulator image for tests.
- **Signing identities.** A release APK and an AAB need an upload key; App Store builds need an Apple Developer
  identity. Which identity publishes the apps (and so whose name the stores show) is decided before T406 and T424.
- **Test devices:** an Android 10+ phone and an iPhone for T407 and T425.
