# Sparemac Helper

This is the source of the one part of [Sparemac](https://sparemac.ai) that runs as administrator. It is published so you can read exactly what it does before you type your password, and check that the helper on your Mac is the one built from it.

Each release of Sparemac is tagged here (`v0.4`, …) with the source it shipped with. [RELEASES.md](RELEASES.md) lists the SHA-256 of the helper in each release.

## What it is

Sparemac gives AI agents their own macOS account on your Mac. Creating and removing those accounts, and signing them in, needs administrator rights, so Sparemac installs this small helper once, when you enter your password during setup.

- **Installed at** `/Library/PrivilegedHelperTools/Sparemac Helper.app`, started by launchd from `/Library/LaunchDaemons/dev.sparemac.helper.plist` (in [Support](Support)).
- **Who can talk to it:** only Sparemac's own app and command, signed by Sparemac's Developer ID team, and only when the person using them is an administrator of the Mac. Everything else is refused (see `listener(_:shouldAcceptNewConnection:)` and the code-signing requirement at the end of [main.swift](Sources/SparemacHelper/main.swift)).
- **It never takes paths or user IDs from the app.** It reads who is asking from the connection itself, and only touches accounts it made (they carry the comment "Sparemac agent account").

## Everything it can do

These are all the commands in [HelperProtocol.swift](Sources/SparemacShared/HelperProtocol.swift). There are no others.

| Command | What it does |
|---|---|
| `createAccount` | Creates a Standard (not administrator) account with `sysadminctl`, sets its password through Open Directory, gives it its own group, and skips its Setup Assistant. |
| `deleteAccount` | Signs a Sparemac account out and removes its home folder and group. It refuses administrators, your own account and root. |
| `signOut` | Logs a Sparemac account out, as the Apple menu does. |
| `removeLeftoverHome` | Removes a deleted session's home folder, only when its owner no longer exists. |
| `installAgent` | Copies Sparemac Tools from the signed app into `/Library/Application Support/Sparemac` and adds its launch agent, which runs only inside Sparemac's accounts. |
| `applyInputSettings` | Copies your trackpad, mouse and keyboard settings into a Sparemac account, so signing it in doesn't reset the shared devices. Only an allowed list of settings. |
| `setScreenSharing` | On: adds a packet-filter rule so only this Mac can connect, then starts Screen Sharing. Off: stops it and removes the rule. Sparemac uses it for a few seconds to sign a session in. |
| `screenSharingState` | Says whether Screen Sharing is running. |
| `updateHelper` | Replaces itself with the helper inside the calling Sparemac app, after checking that copy is signed by Sparemac, so app updates need no new password. |
| `uninstall` | Removes every Sparemac account and everything above. |
| `version` | Answers its signing team. |

## Check the helper on your Mac

Who signed it (the team should be `6D5N473QP3`):

```bash
codesign -dv "/Library/PrivilegedHelperTools/Sparemac Helper.app" 2>&1 | grep -E "Identifier|TeamIdentifier"
```

Its SHA-256, to compare with [RELEASES.md](RELEASES.md) (Sparemac shows the same in Settings › Security):

```bash
shasum -a 256 "/Library/PrivilegedHelperTools/Sparemac Helper.app/Contents/MacOS/SparemacHelper"
```

Everything it has done, with who asked and how it ended (it never logs passwords):

```bash
log show --predicate 'subsystem == "dev.sparemac.helper"' --last 7d
```

## Build it

With the Xcode the app is built with (macOS 15 SDK or later):

```bash
swift build -c release --build-system native
```

The release binary is also signed with Developer ID and notarized, which changes its bytes, so its hash differs from your build. Reading the source, the signature and the log above is how you check it today.

## Licence

Published to read and audit, not to reuse: see [LICENSE](LICENSE).
