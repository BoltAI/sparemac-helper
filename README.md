# Sparemac Helper

This is the source of the one part of [Sparemac](https://sparemac.ai) that runs as administrator. It is published so you can read exactly what it does before you type your password, and check that the tool in your copy of Sparemac is the one built from it.

Each release of Sparemac is tagged here (`v0.4`, …) with the source it shipped with. [RELEASES.md](RELEASES.md) lists the SHA-256 of the tool in each release.

## What it is

Sparemac gives AI agents their own macOS account on your Mac. Creating and deleting those accounts needs administrator rights. Nothing of Sparemac is installed to run as administrator and nothing listens for requests: when you add or delete a session (or turn the firewall on or off, or uninstall), macOS asks for your password, and Sparemac runs this tool as root for that one change. It answers and exits.

- **Where it is:** inside the app, `Sparemac.app/Contents/Resources/Sparemac Helper.app`.
- **How it runs:** after macOS's password prompt, Apple's `bash` copies it into a new folder only root can write, checks the copy's signature with `codesign` (Sparemac's team, identifier `dev.sparemac.helper`), and runs the copy, so what runs is what was checked. The password a new session gets reaches it on its standard input, never on a command line.
- **What it touches:** only accounts it made (they carry the comment "Sparemac agent account"). It refuses administrators, your own account and root.

Signing sessions in needs no administrator: the app signs them in in the background, as you. Sparemac Tools, inside each session, signs its own session out.

## Everything it can do

These are all the commands in [main.swift](Sources/SparemacHelper/main.swift). There are no others.

| Command | What it does |
|---|---|
| `create` | Creates a Standard (not administrator) account with `sysadminctl`, sets its password through Open Directory, gives it its own group, skips its Setup Assistant, and copies in your trackpad, mouse and keyboard settings (only an allowed list). Then keeps every session to itself (below). Also does `install`. |
| `install` | Sets Sparemac Tools to start in sessions: copies it from the app into `/Users/Shared/Sparemac/Tools` (a folder you own, so Sparemac keeps the copy up to date with no password), checks the copy's signature, and adds a launch agent that runs it, only inside Sparemac's accounts. Writes your uid, whom Tools answers. Removes what earlier versions installed. |
| `delete` | Signs a Sparemac account out, removes the rule that keeps it out of people's home folders, and removes its files and group. The app then deletes the account's record. |
| `remove-home` | Removes a deleted session's home folder, only when its owner no longer exists. |
| `sign-out` | Ends a session that didn't sign out by itself. |
| `firewall sessions on\|off`, `firewall screen-sharing on\|off` (and `create --firewall`, setup's choice) | The optional firewall that keeps Sparemac accounts off the local network (private addresses), except to ask the router for DNS. On: a launch daemon runs Apple's `pfctl` at startup with the rules in `/Library/Application Support/Sparemac/firewall.rules`; no Sparemac code runs for it. This Mac's own localhost stays reachable to sessions. `screen-sharing`: Screen Sharing's port (5900) answers only this Mac. |
| `uninstall`, `finish-uninstall` | Removes every Sparemac account's files and everything above; the app deletes the accounts' records in between. |

After `create`, it also keeps sessions to themselves:

- Moves any Sparemac account still in the `staff` group into a group of its own, because macOS opens every person's home folder to `staff`.
- Adds a rule to each person's home folder that turns every Sparemac account away (`<session> deny list,search`), whatever the folder's own permissions say.

## Check the tool in your copy of Sparemac

Who signed it (the team should be `6D5N473QP3`):

```bash
codesign -dv "/Applications/Sparemac.app/Contents/Resources/Sparemac Helper.app" 2>&1 | grep -E "Identifier|TeamIdentifier"
```

Its SHA-256, to compare with [RELEASES.md](RELEASES.md) (Sparemac shows the same in Settings › Security):

```bash
shasum -a 256 "/Applications/Sparemac.app/Contents/Resources/Sparemac Helper.app/Contents/MacOS/SparemacHelper"
```

Everything it has done, and how it ended (it never logs passwords):

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
