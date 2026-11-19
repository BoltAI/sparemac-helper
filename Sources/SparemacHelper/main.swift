import Foundation
import OpenDirectory
import os
import Security
import SparemacShared

signal(SIGPIPE, SIG_IGN) // a closed pipe to the app fails the write instead of killing the helper

// SparemacHelper: Sparemac's admin tool. Nothing installs it and nothing keeps it running: the app runs it, as
// root, only after you type your password in macOS's prompt, for the one change you asked for (creating or
// deleting a session, the firewall, uninstalling), and it exits. The app first copies it to a folder only
// root can write and checks the copy's signature, so what runs is exactly what was checked.
//
//   SparemacHelper install --owner <uid> --app <Sparemac.app>
//   SparemacHelper create <name> <full name> --owner <uid> --app <Sparemac.app>   (stdin: {"password", "inputSettings"})
//   SparemacHelper delete <name> --owner <uid>
//   SparemacHelper remove-home <name>
//   SparemacHelper sign-out <name>
//   SparemacHelper firewall on|off
//   SparemacHelper uninstall --owner <uid>
//   SparemacHelper finish-uninstall                                              (stdin: {"names", "uuids"})
//
// It answers one line of JSON on stdout: {"ok": true, ...} or {"ok": false, "error": "..."}.

let logger = Logger(subsystem: "dev.sparemac.helper", category: "helper")
/// To the unified log (`log show --predicate 'subsystem == "dev.sparemac.helper"'`).
func log(_ text: String) { logger.log("\(text, privacy: .public)") }

/// The team that signed this tool, read from its own signature.
func ownTeam() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    return dict[kSecCodeInfoTeamIdentifier as String] as? String
}

let team = ownTeam()

/// Checks that a bundle is signed by our team with the given identifier.
func signed(_ url: URL, identifier: String, strict: Bool = false) -> Bool {
    guard let team else { return false }
    var code: SecStaticCode?, requirement: SecRequirement?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
          SecRequirementCreateWithString("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\"" as CFString, [], &requirement) == errSecSuccess
    else { return false }
    // Strict: every file of the bundle, nested code too, and no links pointing outside it.
    let flags = kSecCSCheckAllArchitectures | (strict ? (kSecCSStrictValidate | kSecCSCheckNestedCode) : 0)
    return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: flags), requirement) == errSecSuccess
}

enum Ops {
    static let pfAnchor = "com.apple/250.dev.sparemac"
    /// In /var/run, which macOS empties at startup, when the packet filter also starts disabled: a token left
    /// from before a restart would make it look enabled.
    static let pfTokenFile = "/var/run/dev.sparemac.pf-token"
    static let oldPFTokenFile = "\(Sparemac.supportDirectory)/pf-token"

    static func check(_ name: String) throws {
        guard !name.isEmpty, name.count <= 32, name.first.map({ ("a"..."z").contains($0) }) == true,
              name.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) }) else {
            throw Failure("account names use lowercase letters and digits, starting with a letter")
        }
    }

    static func sh(_ path: String, _ args: [String], input: String? = nil) throws -> String {
        let result = run(path, args, input: input)
        guard result.status == 0 else { throw Failure("\((path as NSString).lastPathComponent) failed: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))") }
        return result.output
    }

    static func asUser(_ name: String, _ args: [String]) {
        run("/usr/bin/sudo", ["-u", name, "-H", "--"] + args)
    }

    // MARK: Accounts

    static func createAccount(_ name: String, fullName: String, password: String) throws {
        try check(name)
        let fullName = Accounts.fullName(for: fullName)
        guard !fullName.isEmpty, fullName.count <= 64, !fullName.contains(where: \.isNewline) else { throw Failure("give the account a name") }
        guard Accounts.uid(of: name) == nil else { throw Failure("an account named \(name) already exists") }
        // A group of that name (admin, wheel, staff…) would become the session's own group, and so give it that
        // group's rights; a folder of that name (/Users/Shared…) would become its home, and be wiped with it.
        guard getgrnam(name) == nil else { throw Failure("macOS already has a group named \(name): pick another name") }
        var info = stat()
        guard lstat("/Users/\(name)", &info) != 0 else { throw Failure("/Users/\(name) already exists: pick another name") }
        guard !Accounts.fullNameTaken(fullName) else { throw Failure("another account is already called “\(fullName)”: pick another name") }
        guard password.count >= 8 else { throw Failure("the password needs at least 8 characters") }
        // sysadminctl prints harmless errors on some Macs while still creating the account; check the result.
        // No password on its command line, where any process could read it with ps: it's set just after,
        // through Open Directory.
        let created = run("/usr/sbin/sysadminctl", ["-addUser", name, "-fullName", fullName, "-home", "/Users/\(name)"])
        guard let uid = Accounts.uid(of: name) else { throw Failure("creating \(name) failed: \(created.output.suffix(300))") }
        do { try setPassword(name, password) } catch {
            run("/usr/sbin/sysadminctl", ["-deleteUser", name])
            throw Failure("couldn't set \(name)'s password: \(error.localizedDescription)")
        }

        let gid = try ownGroup(name, uid: uid, fullName: fullName)
        _ = try sh("/usr/bin/dscl", [".", "-create", "/Users/\(name)", "Comment", Sparemac.accountMarker])
        run("/usr/sbin/dseditgroup", ["-o", "edit", "-a", name, "-t", "user", "com.apple.access_screensharing"])

        _ = try sh("/usr/sbin/createhomedir", ["-c", "-u", name])
        _ = try sh("/usr/sbin/chown", ["-R", "\(uid):\(gid)", "/Users/\(name)"])
        // Tells macOS not to run the per-user Setup Assistant (documented by the Mac admin community).
        asUser(name, ["/usr/bin/touch", "/Users/\(name)/.skipbuddy"])
        // No screen saver, so the session never locks itself when idle.
        asUser(name, ["/usr/bin/defaults", "-currentHost", "write", "com.apple.screensaver", "idleTime", "-int", "0"])
        guard FileManager.default.fileExists(atPath: "/Users/\(name)/.skipbuddy") else { throw Failure("couldn't prepare \(name)'s home folder") }
        log("created \(name) uid \(uid) gid \(gid)")
        isolate()
        prepareFolders()
    }

    /// Its own primary group instead of staff, so it can't read what macOS shares with staff: every person's
    /// home folder is open to staff.
    static func ownGroup(_ name: String, uid: uid_t, fullName: String) throws -> gid_t {
        var gid = gid_t(uid)
        if let existing = getgrnam(name) {
            // Only a group Sparemac could have made for this session: never one of macOS's own (admin, wheel…).
            guard existing.pointee.gr_gid >= 501 else { throw Failure("\(name) matches macOS's group \(String(cString: existing.pointee.gr_name))") }
            gid = existing.pointee.gr_gid
        } else {
            if getgrgid(gid) != nil { gid = (600..<1000).map { gid_t($0) }.first { getgrgid($0) == nil } ?? gid }
            _ = try sh("/usr/sbin/dseditgroup", ["-o", "create", "-r", fullName, "-i", "\(gid)", name])
        }
        _ = try sh("/usr/bin/dscl", [".", "-create", "/Users/\(name)", "PrimaryGroupID", "\(gid)"])
        return gid
    }

    // MARK: Folders sessions use

    /// Each session's socket folder, inside the root-owned run folder: only that session can create its socket,
    /// so no account can take another's. And the exchange folder in /Users/Shared, owned by root and you.
    static func prepareFolders(owner: uid_t? = nil) {
        // The old shared socket folder, where anyone could create a socket under any session's name.
        try? FileManager.default.removeItem(atPath: "/Users/Shared/Sparemac/run")
        do {
            try ownedDirectory(Wire.runDirectory, uid: 0, gid: 0, mode: 0o755)
            for name in Accounts.all() {
                guard let entry = getpwnam(name) else { continue }
                try ownedDirectory(Wire.folder(for: name), uid: entry.pointee.pw_uid, gid: entry.pointee.pw_gid, mode: 0o755)
            }
        } catch { log("couldn't prepare the socket folders: \(error)") }
        let ownerUID = owner ?? (try? String(contentsOfFile: Sparemac.ownerFile, encoding: .utf8)).flatMap { uid_t($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        guard let ownerUID else { return }
        do {
            try ownedDirectory("/Users/Shared/Sparemac", uid: 0, gid: 0, mode: 0o755)
            try ownedDirectory(SharedFolder.parent, uid: ownerUID, gid: 20, mode: 0o755)
        } catch { log("couldn't prepare the exchange folder: \(error)") }
    }

    /// Makes `path` a real directory with this owner and mode, never following a link to somewhere else. In a
    /// folder anyone can write to (/Users/Shared), what's there may be anyone's: whatever isn't ours is moved
    /// aside (renaming doesn't follow links) and a fresh directory made in its place.
    static func ownedDirectory(_ path: String, uid: uid_t, gid: gid_t, mode: mode_t) throws {
        var info = stat()
        if lstat(path, &info) == 0 {
            let isDirectory = (info.st_mode & S_IFMT) == S_IFDIR
            if !isDirectory || (info.st_uid != uid && info.st_uid != 0) {
                let aside = "\(path).moved-\(UUID().uuidString.prefix(8))"
                guard rename(path, aside) == 0 else { throw Failure("couldn't move aside \(path)") }
                log("moved aside \(path), which wasn't Sparemac's")
            }
        }
        if lstat(path, &info) != 0 {
            guard mkdir(path, mode) == 0 else { throw Failure("couldn't create \(path): \(String(cString: strerror(errno)))") }
        }
        // Opened without following links, then changed through the open folder.
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { throw Failure("couldn't open \(path)") }
        defer { close(fd) }
        guard fchown(fd, uid, gid) == 0, fchmod(fd, mode) == 0 else { throw Failure("couldn't set up \(path)") }
    }

    // MARK: Keeping sessions to themselves

    /// The people who use this Mac: accounts from UID 501 that aren't Sparemac's, with their home folders.
    static func personHomes() -> [String] {
        let sessions = Set(Accounts.all())
        return run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count == 2, let uid = Int(parts[1]), uid >= 501, !parts[0].hasPrefix("_"), !sessions.contains(String(parts[0])) else { return nil }
            let home = run("/usr/bin/dscl", [".", "-read", "/Users/\(parts[0])", "NFSHomeDirectory"]).output
                .replacingOccurrences(of: "NFSHomeDirectory:", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
            return home.hasPrefix("/Users/") && FileManager.default.fileExists(atPath: home) ? home : nil
        }
    }

    static func homeRule(_ session: String) -> String { "\(session) deny list,search" }

    /// Removes Sparemac's "deny list,search" rules for these accounts (by UUID, as macOS shows them once the
    /// accounts are deleted) from a home folder, last first so the numbers of the others don't move.
    static func removeRules(of uuids: [String], from home: String) {
        guard !uuids.isEmpty else { return }
        let lines = run("/bin/ls", ["-led", home]).output.split(separator: "\n").dropFirst()
        let indexes = lines.compactMap { line -> Int? in
            let text = line.trimmingCharacters(in: .whitespaces)
            guard text.contains("deny list,search"), uuids.contains(where: { text.uppercased().contains($0.uppercased()) }) else { return nil }
            return Int(text.prefix { $0.isNumber })
        }
        for index in indexes.sorted(by: >) { run("/bin/chmod", ["-a#", "\(index)", home]) }
    }

    /// Sessions can't open anyone's home folder: each has its own group (older sessions were in staff), and each
    /// person's home folder has a rule that turns that session away, whatever its permissions say. The firewall
    /// keeps them off the local network.
    static func isolate() {
        let sessions = Accounts.all()
        for name in sessions {
            guard let uid = Accounts.uid(of: name), let entry = getpwnam(name), entry.pointee.pw_gid == 20 else { continue }
            let fullName = String(cString: entry.pointee.pw_gecos)
            do {
                let gid = try ownGroup(name, uid: uid, fullName: fullName.isEmpty ? name : fullName)
                run("/usr/sbin/chown", ["-R", ":\(gid)", "/Users/\(name)"])
                log("moved \(name) out of staff to group \(gid)")
            } catch { log("couldn't give \(name) its own group: \(error.localizedDescription)") }
        }
        for home in personHomes() {
            let rules = run("/bin/ls", ["-led", home]).output
            for name in sessions where !rules.contains("user:\(name) deny list,search") {
                if run("/bin/chmod", ["+a", homeRule(name), home]).status == 0 { log("kept \(name) out of \(home)") }
            }
        }
        refreshFirewall()
    }

    /// Sets an account's password in the local directory, as root, without the old one.
    static func setPassword(_ name: String, _ password: String) throws {
        let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
        let record = try node.record(withRecordType: kODRecordTypeUsers, name: name, attributes: nil)
        try record.changePassword(nil, toPassword: password)
    }

    static func signOut(_ name: String) throws {
        try check(name)
        guard Accounts.isAgentAccount(name), let uid = Accounts.uid(of: name) else { throw Failure("\(name) is not a Sparemac agent account") }
        // Log out as the Apple menu does: the session's own loginwindow gets Apple's "really log out" event
        // (kAEReallyLogOut, QA1134), so apps quit cleanly and the login window stops showing the account as
        // logged in. Tearing the session down instead leaves that check mark behind.
        run("/bin/launchctl", ["asuser", "\(uid)", "/usr/bin/sudo", "-u", name, "--",
                               "/usr/bin/osascript", "-e", "tell application \"loginwindow\" to «event aevtrlgo»"])
        for _ in 0..<40 where Accounts.hasSession(name) { usleep(500_000) }
        // An app that refuses to quit holds the logout up; then end the session.
        if Accounts.hasSession(name) { log("\(name) didn't log out; ending its session"); run("/bin/launchctl", ["bootout", "user/\(uid)"]) }
        for _ in 0..<20 where Accounts.hasSession(name) { usleep(500_000) }
        if Accounts.hasSession(name) { run("/usr/bin/pkill", ["-u", name, "-x", "loginwindow"]) }
        for _ in 0..<20 where Accounts.hasSession(name) { usleep(500_000) }
        if Accounts.hasSession(name) { throw Failure("\(name) didn't sign out") }
    }

    static func deleteAccount(_ name: String, caller: uid_t) throws {
        try check(name)
        guard Accounts.isAgentAccount(name), let uid = Accounts.uid(of: name) else { throw Failure("\(name) is not a Sparemac agent account") }
        guard uid != caller, uid != 0 else { throw Failure("refusing to delete that account") }
        if run("/usr/sbin/dseditgroup", ["-o", "checkmember", "-m", name, "admin"]).output.contains("yes") {
            throw Failure("\(name) is an administrator; Sparemac only deletes its own Standard accounts")
        }
        for home in personHomes() { run("/bin/chmod", ["-a", homeRule(name), home]) }
        try deleteRecord(name, caller: caller)
    }

    // MARK: Input settings

    /// `defaults write` arguments for one simple value, typed as it was.
    static func typed(_ value: Any) -> [String]? {
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return ["-bool", number.boolValue ? "true" : "false"] }
            if CFNumberIsFloatType(number) { return ["-float", number.stringValue] }
            return ["-int", number.stringValue]
        }
        if let string = value as? String { return ["-string", string] }
        return nil
    }

    static func applyInputSettings(_ name: String, settings: Data) throws {
        try check(name)
        guard Accounts.isAgentAccount(name) else { throw Failure("\(name) is not a Sparemac agent account") }
        guard let plist = try PropertyListSerialization.propertyList(from: settings, format: nil) as? [String: Any] else {
            throw Failure("unreadable input settings")
        }
        func write(_ host: [String], _ domain: String, _ values: [String: Any], allowed: (String) -> Bool) {
            for (key, value) in values where allowed(key) {
                guard let typedValue = typed(value) else { continue }
                asUser(name, ["/usr/bin/defaults"] + host + ["write", domain, key] + typedValue)
            }
        }
        for (domain, values) in plist["domains"] as? [String: [String: Any]] ?? [:] where InputSettings.domains.contains(domain) {
            write([], domain, values) { _ in true }
        }
        write([], "-g", plist["global"] as? [String: Any] ?? [:], allowed: InputSettings.allowedGlobal)
        write(["-currentHost"], "-g", plist["globalHost"] as? [String: Any] ?? [:], allowed: InputSettings.allowedGlobal)
        log("applied the owner's input settings to \(name)")
    }

    // MARK: Sparemac Tools

    /// Sparemac Tools runs in every session from a copy in /Users/Shared/Sparemac/Tools, a folder the owner owns:
    /// outside Sparemac.app, so macOS gives its permissions to it and not to Sparemac, and the app keeps the copy
    /// up to date with no password. Writes the launch agent that starts it, the owner's uid (whom it answers) and
    /// the socket folders, and removes what earlier versions installed.
    static func install(owner: uid_t, app: String) throws {
        let source = Sparemac.agentApp(in: URL(fileURLWithPath: app).resolvingSymlinksInPath())
        guard signed(source, identifier: Sparemac.agentLabel, strict: true) else { throw Failure("Sparemac Tools in \(app) isn't signed by Sparemac") }
        guard owner >= 500, let entry = getpwuid(owner) else { throw Failure("no account with uid \(owner)") }

        try ownedDirectory(Sparemac.supportDirectory, uid: 0, gid: 0, mode: 0o755)
        try "\(owner)\n".write(toFile: Sparemac.ownerFile, atomically: true, encoding: .utf8)
        chown(Sparemac.ownerFile, 0, 0); chmod(Sparemac.ownerFile, 0o644)
        prepareFolders(owner: owner)

        // The copy: staged where only root can write, checked there (what goes in is what was checked), given to the
        // owner, and moved into folders the owner owns (anything else there, a link say, is moved aside first).
        let gid = entry.pointee.pw_gid
        let staging = "/private/var/root/.sparemac-tools-\(UUID().uuidString.prefix(8))"
        let toolsChanged = try ToolsCopy.place(source.path, folder: { try ownedDirectory($0, uid: owner, gid: gid, mode: 0o755) },
                                              staging: staging) { copy in
            guard signed(URL(fileURLWithPath: copy), identifier: Sparemac.agentLabel, strict: true) else {
                throw Failure("the copy of Sparemac Tools isn't signed by Sparemac")
            }
            _ = try sh("/usr/sbin/chown", ["-R", "\(owner):\(gid)", copy])
            _ = try sh("/bin/chmod", ["-R", "go-w", copy])
        }
        lchown(Sparemac.agentApp, owner, gid)

        let plist: [String: Any] = [
            "Label": Sparemac.agentLabel,
            "ProgramArguments": [Sparemac.agentExecutable],
            "AssociatedBundleIdentifiers": Sparemac.appBundleID,
            "LimitLoadToSessionType": "Aqua",
            "ProcessType": "Interactive",
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let plistChanged = (try? Data(contentsOf: URL(fileURLWithPath: Sparemac.agentLaunchAgent))) != data
        let changed = plistChanged || toolsChanged
        if plistChanged {
            try data.write(to: URL(fileURLWithPath: Sparemac.agentLaunchAgent))
            chown(Sparemac.agentLaunchAgent, 0, 0); chmod(Sparemac.agentLaunchAgent, 0o644)
        }
        removeLegacy()
        // Sessions signed in now run the old Tools, or none: start the one this launch agent names.
        if changed {
            for name in Accounts.all() {
                guard let uid = Accounts.uid(of: name), Accounts.hasSession(name) else { continue }
                restartAgent(uid: uid)
            }
        }
        log("Sparemac Tools runs from \(Sparemac.agentApp) for owner uid \(owner)")
    }

    /// The helper earlier versions kept running as root, and the copy of Sparemac Tools it installed.
    static func removeLegacy() {
        if FileManager.default.fileExists(atPath: Sparemac.Legacy.helperPlist) {
            run("/bin/launchctl", ["bootout", "system/\(Sparemac.helperLabel)"])
            try? FileManager.default.removeItem(atPath: Sparemac.Legacy.helperPlist)
            log("removed the helper that ran all the time")
        }
        try? FileManager.default.removeItem(atPath: Sparemac.Legacy.helperApp)
        try? FileManager.default.removeItem(atPath: Sparemac.Legacy.agentApp)
        try? FileManager.default.removeItem(atPath: Sparemac.Legacy.oldAgentApp)
        try? FileManager.default.removeItem(atPath: oldPFTokenFile)
        // Its packet filter rules (Screen Sharing's port, sessions off the network), unless the firewall is on now.
        if !firewallOn { releasePF() }
    }

    /// Stops Sparemac Tools in a session and starts the installed one. The stop finishes in the background,
    /// and starting again before it has fails ("Bootstrap failed: 5"), so this waits and retries.
    static func restartAgent(uid: uid_t) {
        let job = "gui/\(uid)/\(Sparemac.agentLabel)"
        run("/bin/launchctl", ["bootout", job])
        run("/usr/bin/pkill", ["-U", "\(uid)", "-x", "SparemacAgent"])
        for _ in 0..<50 where run("/bin/launchctl", ["print", job]).status == 0 { usleep(100_000) }
        for attempt in 1...5 {
            let result = run("/bin/launchctl", ["bootstrap", "gui/\(uid)", Sparemac.agentLaunchAgent])
            if result.status == 0 || run("/bin/launchctl", ["print", job]).status == 0 { return }
            log("starting SparemacAgent for uid \(uid) failed (try \(attempt)): \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
            sleep(1)
        }
    }

    // MARK: Firewall (optional)

    static var sessionsRuleOn: Bool { FileManager.default.fileExists(atPath: Sparemac.firewallSessionsMarker) }
    static var screenSharingRuleOn: Bool { FileManager.default.fileExists(atPath: Sparemac.firewallScreenSharingMarker) }
    /// Any rule is on: the startup job loads them.
    static var firewallOn: Bool { sessionsRuleOn || screenSharingRuleOn }

    /// Run at every startup by launchd, as root: only Apple's pfctl, with the rules file next to it.
    static let firewallScriptText = """
    #!/bin/sh
    # Sparemac: keeps sessions off the local network. Started by launchd at startup, and by Sparemac's admin
    # tool when sessions change. Only Apple's pfctl runs, with the rules in firewall.rules.
    T=\(pfTokenFile)
    R='\(Sparemac.firewallRules)'
    [ -f "$R" ] || exit 0
    if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled' || [ ! -s "$T" ]; then
        [ -s "$T" ] && /sbin/pfctl -X "$(/bin/cat "$T")" >/dev/null 2>&1
        /sbin/pfctl -E 2>&1 | /usr/bin/awk -F': ' '/Token/ { print $2 }' > "$T"
    fi
    exec /sbin/pfctl -a \(pfAnchor) -f "$R"

    """

    /// Screen Sharing (port 5900) answers only this Mac. Sessions reach the internet (and their router's DNS) but
    /// not the local network. This Mac's own localhost stays open to them: the packet filter can't tell a session's
    /// connection to a server of yours from your own, so blocking it would also block servers the session runs.
    static func firewallRulesText() -> String {
        var rules = ""
        if screenSharingRuleOn {
            rules += """
            pass in quick on lo0 proto { tcp, udp } from any to any port 5900
            block drop in quick proto { tcp, udp } from any to any port 5900

            """
        }
        let uids = Accounts.all().compactMap { Accounts.uid(of: $0) }
        if sessionsRuleOn, !uids.isEmpty {
            let users = "{ " + uids.map(String.init).joined(separator: ", ") + " }"
            rules += """
            table <sparemac_local> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, fc00::/7, fe80::/10 }
            pass out quick proto { tcp, udp } from any to <sparemac_local> port 53 user \(users)
            block return out quick proto { tcp, udp } from any to <sparemac_local> user \(users)

            """
        }
        return rules
    }

    /// Turns one rule on or off: `sessions` (off the local network) or `screen-sharing` (this Mac only).
    static func setRule(_ rule: String, _ on: Bool) throws {
        let marker: String
        switch rule {
        case "sessions": marker = Sparemac.firewallSessionsMarker
        case "screen-sharing": marker = Sparemac.firewallScreenSharingMarker
        default: throw Failure("unknown firewall rule \(rule)")
        }
        try ownedDirectory(Sparemac.supportDirectory, uid: 0, gid: 0, mode: 0o755)
        if on {
            guard FileManager.default.createFile(atPath: marker, contents: nil, attributes: [.posixPermissions: 0o644]) else {
                throw Failure("couldn't turn on the firewall rule")
            }
            chown(marker, 0, 0)
        } else {
            try? FileManager.default.removeItem(atPath: marker)
        }
        try setFirewall(firewallOn)
        log("firewall rule \(rule) \(on ? "on" : "off")")
    }

    /// The startup job and rules file while any rule is on; nothing when none is.
    static func setFirewall(_ on: Bool) throws {
        if on {
            try ownedDirectory(Sparemac.supportDirectory, uid: 0, gid: 0, mode: 0o755)
            try firewallScriptText.write(toFile: Sparemac.firewallScript, atomically: true, encoding: .utf8)
            chown(Sparemac.firewallScript, 0, 0); chmod(Sparemac.firewallScript, 0o755)
            try writeFirewallRules()
            let plist: [String: Any] = [
                "Label": Sparemac.firewallLabel,
                "ProgramArguments": ["/bin/sh", Sparemac.firewallScript],
                "RunAtLoad": true,
            ]
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try data.write(to: URL(fileURLWithPath: Sparemac.firewallPlist))
            chown(Sparemac.firewallPlist, 0, 0); chmod(Sparemac.firewallPlist, 0o644)
            run("/bin/launchctl", ["bootout", "system/\(Sparemac.firewallLabel)"])
            run("/bin/launchctl", ["bootstrap", "system", Sparemac.firewallPlist])
            try applyFirewallNow()
            log("firewall on")
        } else {
            run("/bin/launchctl", ["bootout", "system/\(Sparemac.firewallLabel)"])
            for path in [Sparemac.firewallPlist, Sparemac.firewallScript, Sparemac.firewallRules,
                         Sparemac.firewallSessionsMarker, Sparemac.firewallScreenSharingMarker] { try? FileManager.default.removeItem(atPath: path) }
            releasePF()
            log("firewall off")
        }
    }

    static func writeFirewallRules() throws {
        try firewallRulesText().write(toFile: Sparemac.firewallRules, atomically: true, encoding: .utf8)
        chown(Sparemac.firewallRules, 0, 0); chmod(Sparemac.firewallRules, 0o644)
    }

    static func applyFirewallNow() throws {
        let result = run("/bin/sh", [Sparemac.firewallScript])
        guard result.status == 0 else { throw Failure("the firewall didn't load: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))") }
        guard run("/sbin/pfctl", ["-s", "info"]).output.contains("Status: Enabled") else { throw Failure("the packet filter didn't start") }
    }

    /// After sessions change: the rules list them by uid.
    static func refreshFirewall() {
        guard firewallOn else { return }
        do { try writeFirewallRules(); try applyFirewallNow() } catch { log("couldn't update the firewall: \(error)") }
    }

    static func releasePF() {
        run("/sbin/pfctl", ["-a", pfAnchor, "-F", "all"])
        if let token = try? String(contentsOfFile: pfTokenFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty {
            run("/sbin/pfctl", ["-X", token])
        }
        try? FileManager.default.removeItem(atPath: pfTokenFile)
    }

    // MARK: Removing

    /// An agent account signed out, out of its groups, and its record deleted: macOS lets this tool do that, run
    /// for Sparemac, once you allow Sparemac to administer your computer (a launchd job can't). Its files go after
    /// (removeLeftoverHome), in a job of their own, as macOS lets go of them once the record is gone.
    static func deleteRecord(_ name: String, caller: uid_t) throws {
        try check(name)
        guard Accounts.isAgentAccount(name), let uid = Accounts.uid(of: name), uid != caller, uid != 0 else { return }
        if Accounts.hasSession(name) { try? signOut(name) }
        run("/usr/bin/pkill", ["-9", "-u", name])
        run("/usr/sbin/dseditgroup", ["-o", "edit", "-d", name, "-t", "user", "com.apple.access_screensharing"])
        if getgrnam(name) != nil { run("/usr/sbin/dseditgroup", ["-o", "delete", name]) }
        let deleted = run("/usr/bin/dscl", [".", "-delete", "/Users/\(name)"])
        guard deleted.status == 0 else {
            throw Failure("macOS didn't let Sparemac delete \(name)'s account (allow Sparemac to administer your computer): \(deleted.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        log("deleted \(name)'s account")
    }

    /// Runs Apple's programs as a one-time root job of launchd's, and waits for it: what they touch isn't put down
    /// to Sparemac (macOS would ask whether Sparemac may open a session's photo library, say, while removing its
    /// home folder). Answers the exit status, or -1.
    static func runDetached(_ arguments: [String], timeout: TimeInterval = 600) -> Int32 {
        let label = "dev.sparemac.admin.\(UUID().uuidString.prefix(8).lowercased())"
        let plistPath = "/private/var/run/\(label).plist"
        // RunAtLoad without KeepAlive: it runs once and stays listed, with its exit status, until booted out.
        let plist: [String: Any] = ["Label": label, "ProgramArguments": arguments, "RunAtLoad": true]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
              (try? data.write(to: URL(fileURLWithPath: plistPath))) != nil else { return -1 }
        defer {
            run("/bin/launchctl", ["bootout", "system/\(label)"])
            try? FileManager.default.removeItem(atPath: plistPath)
        }
        chmod(plistPath, 0o644)
        guard run("/bin/launchctl", ["bootstrap", "system", plistPath]).status == 0 else { return -1 }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let printed = run("/bin/launchctl", ["print", "system/\(label)"])
            guard printed.status == 0 else { return -2 }  // gone: it ran (or never could)
            let info = printed.output
            if info.contains("state = not running"), let range = info.range(of: "last exit code = "),
               let code = Int32(info[range.upperBound...].prefix { $0 == "-" || $0.isNumber }) {
                return code
            }
            usleep(200_000)
        }
        return -1
    }

    /// Deletes what it can of a session's home folder. While the account exists, macOS 27 doesn't let a
    /// process without Full Disk Access (which Sparemac doesn't ask for) delete the home's own folders, even
    /// as root: an empty skeleton stays until removeLeftoverHome, after the account is deleted.
    static func removeHome(_ home: String) {
        guard FileManager.default.fileExists(atPath: home) else { return }
        let status = isDetached ? run("/bin/rm", ["-rf", home]).status : runDetached(["/bin/rm", "-rf", home])
        if FileManager.default.fileExists(atPath: home) { log("kept for now: parts of \(home) (rm: \(status))") }
    }

    static func removeLeftoverHome(_ name: String) throws {
        try check(name)
        let home = "/Users/\(name)"
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: home) else { return }
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value ?? 0
        // Asked of Open Directory itself: this process's own lookups (getpwnam) keep answering from a cache
        // for a while after the record is deleted.
        func recordExists() -> Bool { run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "RecordName"]).status == 0 }
        func ownerExists() -> Bool {
            !run("/usr/bin/dscl", [".", "-search", "/Users", "UniqueID", "\(owner)"]).output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        for _ in 0..<20 where recordExists() { usleep(500_000) }
        guard !recordExists() else { throw Failure("\(name) still has an account") }
        guard owner >= 500, !ownerExists() else { throw Failure("\(home) belongs to an account") }
        removeHome(home)
        try? FileManager.default.removeItem(atPath: SharedFolder.path(for: name))
        try? FileManager.default.removeItem(atPath: Wire.folder(for: name))
        if FileManager.default.fileExists(atPath: home) { throw Failure("macOS kept \(home)") }
        log("removed \(home)")
    }

    /// The sessions' records (as deleteRecord does): the rest, in finishUninstall, runs as a job. Answers the
    /// sessions' names and UUIDs (home-folder rules name deleted accounts by UUID).
    static func uninstallRecords(owner: uid_t) -> (names: [String], uuids: [String], problems: [String]) {
        var problems: [String] = []
        let names = Accounts.all()
        let uuids = names.compactMap { name -> String? in
            run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "GeneratedUID"]).output
                .split(separator: " ").last.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        }
        let homes = personHomes()
        for name in names {
            for home in homes { run("/bin/chmod", ["-a", homeRule(name), home]) }
            do { try deleteRecord(name, caller: owner) } catch { problems.append("\(error)") }
        }
        return (names, uuids, problems)
    }

    /// Everything else Sparemac added: the sessions' files, the rules naming them, the firewall, Sparemac Tools,
    /// the folders, and what earlier versions installed.
    static func finishUninstall(names: [String], uuids: [String], owner: uid_t?) {
        for name in names {
            do { try removeLeftoverHome(name) } catch { log("kept /Users/\(name): \(error)") }
        }
        for home in personHomes() { removeRules(of: uuids, from: home) }
        try? setFirewall(false)
        releasePF()
        try? FileManager.default.removeItem(atPath: Sparemac.agentLaunchAgent)
        removeLegacy()
        try? FileManager.default.removeItem(atPath: Sparemac.supportDirectory)
        try? FileManager.default.removeItem(atPath: "/Users/Shared/Sparemac")
        // The record of what AI agents did, kept in the owner's account.
        if let owner, let home = getpwuid(owner).map({ String(cString: $0.pointee.pw_dir) }) {
            try? FileManager.default.removeItem(atPath: "\(home)/Library/Logs/Sparemac")
        }
        log("uninstalled")
    }
}

// MARK: - Command line

/// Running as the one-time launchd job (see runSelfDetached), not for Sparemac.
var isDetached = false
/// The job's input and answer, in files only root can read, as it has no stdin or stdout of the tool's.
var inputPath: String?, outputPath: String?

/// Answers one line of JSON and exits.
func answer(_ reply: [String: Any]) -> Never {
    var reply = reply
    if reply["ok"] == nil { reply["ok"] = true }
    let data = (try? JSONSerialization.data(withJSONObject: reply)) ?? Data(#"{"ok":false,"error":"unreadable answer"}"#.utf8)
    if let outputPath { try? data.write(to: URL(fileURLWithPath: outputPath), options: .atomic) }
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(reply["ok"] as? Bool == true ? 0 : 1)
}

/// The one line of JSON the app sends on stdin (or, in the job, the file it was put in), for what mustn't go on a
/// command line (a password).
func input() -> [String: Any] {
    if let inputPath {
        let data = (try? Data(contentsOf: URL(fileURLWithPath: inputPath))) ?? Data()
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }
    var line = Data()
    while true {
        let byte = FileHandle.standardInput.readData(ofLength: 1)
        if byte.isEmpty || byte == Data([0x0A]) { break }
        line.append(byte)
        if line.count > 1 << 20 { break }
    }
    return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] ?? [:]
}

/// Runs this tool again, with these arguments, as a one-time root job of launchd's, and answers its answer: what
/// it does isn't put down to Sparemac, so macOS asks nothing more (creating an account would ask whether
/// Sparemac may administer your computer; removing a home folder, whether it may open its photo library).
func runSelfDetached(_ args: [String], input: [String: Any]) throws -> [String: Any] {
    guard let executable = Bundle.main.executablePath else { throw Failure("couldn't find the admin tool") }
    let id = UUID().uuidString.prefix(8).lowercased()
    let inFile = "/private/var/run/sparemac-admin-\(id).in", outFile = "/private/var/run/sparemac-admin-\(id).out"
    defer { try? FileManager.default.removeItem(atPath: inFile); try? FileManager.default.removeItem(atPath: outFile) }
    let data = try JSONSerialization.data(withJSONObject: input)
    guard FileManager.default.createFile(atPath: inFile, contents: data, attributes: [.posixPermissions: 0o600]) else {
        throw Failure("couldn't hand the job its input")
    }
    let status = Ops.runDetached([executable, "--detached", "--input", inFile, "--output", outFile] + args)
    guard let reply = (try? Data(contentsOf: URL(fileURLWithPath: outFile))).flatMap({ try? JSONSerialization.jsonObject(with: $0) }) as? [String: Any] else {
        throw Failure("the admin tool's job didn't finish (\(status))")
    }
    guard reply["ok"] as? Bool == true else { throw Failure(reply["error"] as? String ?? "the admin tool's job failed") }
    return reply
}

let original = Array(CommandLine.arguments.dropFirst())
var arguments = original
/// `--name value` from the arguments, taken out of them.
func option(_ name: String) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    let value = arguments[index + 1]
    arguments.removeSubrange(index...(index + 1))
    return value
}

guard geteuid() == 0 else { answer(["ok": false, "error": "Sparemac's admin tool runs only through macOS's password prompt"]) }
// Root in full: sudo and launchctl asuser look at the real user too.
_ = setuid(0)
guard team != nil else { log("unsigned admin tool; refusing to run"); answer(["ok": false, "error": "Sparemac's admin tool isn't signed"]) }

if let index = arguments.firstIndex(of: "--detached") { isDetached = true; arguments.remove(at: index) }
/// create: also turn the firewall on (setup offers it, in the same password prompt).
var withFirewall = false
if let index = arguments.firstIndex(of: "--firewall") { withFirewall = true; arguments.remove(at: index) }
inputPath = option("--input")
outputPath = option("--output")
let owner = option("--owner").flatMap { uid_t($0) }
let app = option("--app")
let command = arguments.first ?? ""
let rest = Array(arguments.dropFirst())
log("\(command): run by uid \(owner.map(String.init) ?? "?")\(isDetached ? " (job)" : "")")

/// What runs as the job: everything but deleting account records.
let asJob: Set<String> = ["install", "create", "remove-home", "sign-out", "firewall", "finish-uninstall"]

do {
    var reply: [String: Any] = [:]
    if asJob.contains(command), !isDetached {
        answer(try runSelfDetached(original, input: input()))
    }
    switch command {
    case "install":
        guard let owner, let app else { throw Failure("install needs --owner and --app") }
        try Ops.install(owner: owner, app: app)
    case "create":
        guard rest.count == 2, let owner, let app else { throw Failure("create needs a name, a full name, --owner and --app") }
        let details = input()
        guard let password = details["password"] as? String else { throw Failure("no password given") }
        try Ops.install(owner: owner, app: app)
        try Ops.createAccount(rest[0], fullName: rest[1], password: password)
        if let settings = (details["inputSettings"] as? String).flatMap({ Data(base64Encoded: $0) }) {
            try? Ops.applyInputSettings(rest[0], settings: settings)
        }
        Ops.prepareFolders(owner: owner)
        if withFirewall, !Ops.sessionsRuleOn { try Ops.setRule("sessions", true) } else { Ops.refreshFirewall() }
    case "delete":
        // The record, run for Sparemac; then its files, as a job.
        guard rest.count == 1, let owner else { throw Failure("delete needs a name and --owner") }
        try Ops.deleteAccount(rest[0], caller: owner)
        _ = try runSelfDetached(["remove-home", rest[0]], input: [:])
    case "remove-home":
        guard rest.count == 1 else { throw Failure("remove-home needs a name") }
        try Ops.removeLeftoverHome(rest[0])
        Ops.refreshFirewall()
    case "sign-out":
        guard rest.count == 1 else { throw Failure("sign-out needs a name") }
        try Ops.signOut(rest[0])
    case "firewall":
        // firewall sessions|screen-sharing on|off
        guard rest.count == 2, ["on", "off"].contains(rest[1]) else { throw Failure("firewall sessions|screen-sharing on|off") }
        try Ops.setRule(rest[0], rest[1] == "on")
    case "uninstall":
        // The records, run for Sparemac; then everything else, as a job.
        guard let owner else { throw Failure("uninstall needs --owner") }
        let (names, uuids, problems) = Ops.uninstallRecords(owner: owner)
        _ = try runSelfDetached(["finish-uninstall", "--owner", "\(owner)"], input: ["names": names, "uuids": uuids])
        reply["uuids"] = uuids
        if !problems.isEmpty { throw Failure(problems.joined(separator: "; ")) }
    case "finish-uninstall":
        let details = input()
        Ops.finishUninstall(names: (details["names"] as? [String] ?? []).filter { (try? Ops.check($0)) != nil },
                            uuids: details["uuids"] as? [String] ?? [], owner: owner)
    default:
        throw Failure("unknown command \(command)")
    }
    log("\(command): done")
    answer(reply)
} catch {
    log("\(command): failed: \(error)")
    answer(["ok": false, "error": "\(error)"])
}
