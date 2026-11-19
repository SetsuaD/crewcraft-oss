# Release acceptance

A release is accepted when every check below passes on a **clean machine** for each platform it ships: a fresh
operating-system install (or a fresh VM or container from the vendor's image) that has never had CrewCraft on it. A
check that cannot run is recorded as *not run*, never as passed. The results go in the release notes (task T308).

## The machines

| Platform | Clean machine | Packages under test |
|---|---|---|
| Linux x86_64 | Ubuntu 24.04 desktop and Debian 12, fresh | `crewcraft-<v>-linux-x86_64.deb`, `.AppImage`; `crewcraft-server-<v>-linux-x86_64.tar.gz` |
| Windows x86_64 | Windows 11, fresh, standard user plus one administrator | `crewcraft-<v>-windows-x86_64.msi`; `crewcraft-server-<v>-windows-x86_64.zip` |
| macOS | macOS 14 or later, fresh user | `crewcraft-<v>-macos-universal.dmg`; `crewcraft-server-<v>-macos-universal.tar.gz` |

## 1. Downloads are what the release says

1. Download every asset and `SHA256SUMS.txt` from the release page.
2. `sha256sum -c SHA256SUMS.txt` (Windows: `Get-FileHash -Algorithm SHA256`) matches every line.

## 2. Server

On one machine per platform:

1. Unpack the server archive. `crewcraft-server --version` prints the release version.
2. `crewcraft-server first-run <new-directory> --name <the machine's name> --admin admin@example.org --listen 0.0.0.0:7443`
   in an interactive terminal prints the root fingerprint and an invitation link. The directory's settings file is
   readable by its owner only (Linux and macOS: mode `0600`).
3. `crewcraft-server first-run` on the same directory again refuses and changes nothing.
4. `crewcraft-server serve <directory>` keeps running.
5. **Dark check**, from another machine: `openssl s_client -connect <server>:7443` without a client certificate fails the
   handshake, and a raw request receives zero application bytes.

## 3. Desktop client, two people

1. Install the client package as a standard user (the MSI may ask for administrator approval; the deb and the DMG are
   installed the platform's usual way). The app appears in the Start menu, application menu or Applications folder
   with the CrewCraft icon.
2. Person A opens the app, pastes the invitation link, chooses a password, adds the authenticator entry shown, types
   its first code, and reaches the sign-in screen.
3. A signs in with email, password and a fresh authenticator code.
4. The administrator invites person B (`crewcraft-server invite`), creates a room with A as owner
   (`crewcraft-server room`) and adds B (`crewcraft-server add-member`).
5. B enrolls and signs in the same way on a second machine of a **different** platform.
6. A sends a message in the room; it appears on B's screen. B replies; it appears on A's.
7. Quit and reopen the app on A: it still knows its server (no new invitation needed) and asks only to sign in.
8. A wrong authenticator code, or a reused one, is refused, and the window says so.

## 4. Upgrade and removal

1. Install the previous release first (from the second beta on), then the new one over it: the app keeps its enrolled
   server.
2. Uninstall from the platform's usual place (Settings → Apps, the package manager, or by deleting the app on macOS).
   The program files are gone; the enrolled-device file in the user's data folder is kept unless the person removes
   it, and the release notes say where it is.

## What each beta is allowed to lack

The first beta's builds are not code-signed: Windows SmartScreen warns before the installer runs, and macOS needs the
app opened from the context menu the first time. Those warnings are expected and are not failures; anything else
unexpected is.
