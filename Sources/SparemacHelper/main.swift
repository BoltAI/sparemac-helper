import Foundation
import OpenDirectory
import os
import Security
import SparemacShared

// SparemacHelper: Sparemac's privileged helper, registered by the app with SMAppService and run by
// launchd as root on demand. It does only what HelperProtocol lists, and only for callers signed by
// the same team as itself with Sparemac's own identifiers.

let logger = Logger(subsystem: "dev.sparemac.helper", category: "helper")
/// To the unified log (`log show --predicate 'subsystem == "dev.sparemac.helper"'`).
func log(_ text: String) { logger.log("\(text, privacy: .public)") }

/// The team that signed this helper, read from its own signature.
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

/// The app bundle of the process that called: …/Sparemac.app/Contents/MacOS/Sparemac.
func callerBundle(_ pid: pid_t) -> URL? {
    var buffer = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
    var url = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
    while url.path != "/" {
        if url.pathExtension == "app" { return url }
        url.deleteLastPathComponent()
    }
    return nil
}

/// Checks that a bundle is signed by our team with the given identifier.
func signed(_ url: URL, identifier: String) -> Bool {
    guard let team else { return false }
    var code: SecStaticCode?, requirement: SecRequirement?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
          SecRequirementCreateWithString("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\"" as CFString, [], &requirement) == errSecSuccess
    else { return false }
    return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), requirement) == errSecSuccess
}

enum Ops {
    static let screenSharingLabel = "system/com.apple.screensharing"
    static let screenSharingPlist = "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
    static let pfAnchor = "com.apple/250.dev.sparemac"
    static let pfTokenFile = "\(Sparemac.supportDirectory)/pf-token"

    static func check(_ name: String) throws {
        guard !name.isEmpty, name.count <= 32, name.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) }) else {
            throw Failure("account names use lowercase letters and digits")
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

        // Its own primary group instead of staff, so it can't read folders shared with staff (your home is).
        var gid = uid
        if getgrgid(gid) != nil { gid = (600..<1000).map { gid_t($0) }.first { getgrgid($0) == nil } ?? uid }
        if getgrnam(name) == nil {
            _ = try sh("/usr/sbin/dseditgroup", ["-o", "create", "-r", fullName, "-i", "\(gid)", name])
        } else if let existing = getgrnam(name) { gid = existing.pointee.gr_gid }
        _ = try sh("/usr/bin/dscl", [".", "-create", "/Users/\(name)", "PrimaryGroupID", "\(gid)"])
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
        run("/bin/launchctl", ["bootout", "user/\(uid)"])
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
        try removeAccountData(name, caller: caller)
        log("removed \(name)'s data; the app deletes the record")
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

    // MARK: Agent

    static func installAgent(owner: uid_t, callerPID: pid_t) throws {
        guard let app = callerBundle(callerPID) else { throw Failure("couldn't find the Sparemac app that asked") }
        let source = app.appendingPathComponent("Contents/Resources/SparemacAgent.app")
        guard FileManager.default.fileExists(atPath: source.path) else { throw Failure("Sparemac Tools is missing from \(app.path); reinstall Sparemac") }
        guard signed(source, identifier: Sparemac.agentLabel) else { throw Failure("Sparemac Tools in \(app.path) isn't signed by Sparemac") }
        let dest = "\(Sparemac.supportDirectory)/SparemacAgent.app"
        try FileManager.default.createDirectory(atPath: Sparemac.supportDirectory, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(atPath: dest)
        _ = try sh("/usr/bin/ditto", [source.path, dest])
        try "\(owner)\n".write(toFile: Sparemac.ownerFile, atomically: true, encoding: .utf8)
        _ = try sh("/usr/sbin/chown", ["-R", "root:wheel", Sparemac.supportDirectory])
        _ = try sh("/bin/chmod", ["-R", "go-w", Sparemac.supportDirectory])
        // Shared folder for the agents' sockets: anyone may create one, nobody may remove another's.
        try FileManager.default.createDirectory(atPath: Wire.runDirectory, withIntermediateDirectories: true)
        chmod("/Users/Shared/Sparemac", 0o1777); chmod(Wire.runDirectory, 0o1777)

        let plist: [String: Any] = [
            "Label": Sparemac.agentLabel,
            "ProgramArguments": ["\(dest)/Contents/MacOS/SparemacAgent"],
            "AssociatedBundleIdentifiers": Sparemac.appBundleID,
            "LimitLoadToSessionType": "Aqua",
            "ProcessType": "Interactive",
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: Sparemac.agentLaunchAgent))
        chown(Sparemac.agentLaunchAgent, 0, 0); chmod(Sparemac.agentLaunchAgent, 0o644)

        for name in Accounts.all() {
            guard let uid = Accounts.uid(of: name), Accounts.hasSession(name) else { continue }
            restartAgent(uid: uid)
        }
        log("installed SparemacAgent for owner uid \(owner)")
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

    // MARK: Screen Sharing

    static func screenSharingLoaded() -> Bool { run("/bin/launchctl", ["print", screenSharingLabel]).status == 0 }

    static func portOpen() -> Bool {
        run("/usr/bin/nc", ["-z", "-G", "1", "127.0.0.1", "5900"]).status == 0
    }

    static func setScreenSharing(_ on: Bool) throws {
        if on {
            try allowOnlyThisMac()
            run("/bin/launchctl", ["enable", screenSharingLabel])
            if !screenSharingLoaded() { run("/bin/launchctl", ["bootstrap", "system", screenSharingPlist]) }
            for _ in 0..<20 where !portOpen() { usleep(250_000) }
            guard portOpen() else { throw Failure("Screen Sharing didn't start") }
        } else {
            run("/bin/launchctl", ["bootout", screenSharingLabel])
            run("/bin/launchctl", ["disable", screenSharingLabel])
            releasePF()
        }
    }

    /// While Screen Sharing is on, a packet filter rule refuses port 5900 from anywhere but this Mac.
    static func allowOnlyThisMac() throws {
        if !FileManager.default.fileExists(atPath: pfTokenFile) {
            let enabled = run("/sbin/pfctl", ["-E"]).output
            if let token = enabled.split(separator: "\n").first(where: { $0.contains("Token") })?.split(separator: ":").last {
                try? FileManager.default.createDirectory(atPath: Sparemac.supportDirectory, withIntermediateDirectories: true)
                try? token.trimmingCharacters(in: .whitespaces).write(toFile: pfTokenFile, atomically: true, encoding: .utf8)
            }
        }
        let rules = """
        pass in quick on lo0 proto tcp from any to any port 5900
        block drop in quick proto tcp from any to any port 5900
        block drop in quick proto udp from any to any port 5900

        """
        _ = try sh("/sbin/pfctl", ["-a", pfAnchor, "-f", "-"], input: rules)
    }

    static func releasePF() {
        run("/sbin/pfctl", ["-a", pfAnchor, "-F", "all"])
        if let token = try? String(contentsOfFile: pfTokenFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty {
            run("/sbin/pfctl", ["-X", token])
        }
        try? FileManager.default.removeItem(atPath: pfTokenFile)
    }

    // MARK: Updating itself

    static func updateHelper(callerPID: pid_t) throws {
        guard let app = callerBundle(callerPID) else { throw Failure("couldn't find the Sparemac app that asked") }
        let source = app.appendingPathComponent("Contents/Resources/Sparemac Helper.app")
        guard signed(source, identifier: Sparemac.helperLabel) else { throw Failure("the helper in \(app.path) isn't signed by Sparemac") }
        let temp = "/Library/PrivilegedHelperTools/.Sparemac Helper.new.app"
        try? FileManager.default.removeItem(atPath: temp)
        _ = try sh("/usr/bin/ditto", [source.path, temp])
        _ = try sh("/usr/sbin/chown", ["-R", "root:wheel", temp])
        try? FileManager.default.removeItem(atPath: Sparemac.helperApp)
        try FileManager.default.moveItem(atPath: temp, toPath: Sparemac.helperApp)
        // launchd starts the new copy on the next call once this one exits.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { exit(0) }
        log("updated from \(app.path)")
    }

    // MARK: Uninstall

    /// Everything of an agent account except its user record, which macOS lets only an app the
    /// user can answer delete (the app does that itself).
    static func removeAccountData(_ name: String, caller: uid_t) throws {
        try check(name)
        guard Accounts.isAgentAccount(name), let uid = Accounts.uid(of: name), uid != caller, uid != 0 else { return }
        if Accounts.hasSession(name) { try? signOut(name) }
        run("/usr/bin/pkill", ["-9", "-u", name])
        run("/usr/sbin/dseditgroup", ["-o", "edit", "-d", name, "-t", "user", "com.apple.access_screensharing"])
        if getgrnam(name) != nil { run("/usr/sbin/dseditgroup", ["-o", "delete", name]) }
        removeHome("/Users/\(name)")
        try? FileManager.default.removeItem(atPath: SharedFolder.path(for: name))
    }

    /// Deletes what it can of a session's home folder. While the account exists, macOS 27 doesn't let a
    /// process without Full Disk Access (which Sparemac doesn't ask for) delete the home's own folders, even
    /// as root: an empty skeleton stays until removeLeftoverHome, after the account is deleted.
    static func removeHome(_ home: String) {
        guard FileManager.default.fileExists(atPath: home) else { return }
        let removed = run("/bin/rm", ["-rf", home])
        if FileManager.default.fileExists(atPath: home) {
            log("kept for now: parts of \(home) (\(removed.output.split(separator: "\n").count) refused)")
        }
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
        if FileManager.default.fileExists(atPath: home) { throw Failure("macOS kept \(home)") }
        log("removed the leftover \(home)")
    }

    static func uninstall(caller: uid_t) throws {
        var problems: [String] = []
        for name in Accounts.all() {
            do { try removeAccountData(name, caller: caller) } catch { problems.append("\(error)") }
        }
        releasePF()
        try? FileManager.default.removeItem(atPath: Sparemac.agentLaunchAgent)
        try? FileManager.default.removeItem(atPath: Sparemac.supportDirectory)
        try? FileManager.default.removeItem(atPath: "/Users/Shared/Sparemac")
        // The record of what AI agents did, kept in the owner's account.
        if let home = getpwuid(caller).map({ String(cString: $0.pointee.pw_dir) }) {
            try? FileManager.default.removeItem(atPath: "\(home)/Library/Logs/Sparemac")
        }
        if !problems.isEmpty { throw Failure(problems.joined(separator: "; ")) }
        // Last, the helper itself: its files now, its launchd job a moment after this reply.
        try? FileManager.default.removeItem(atPath: Sparemac.helperPlist)
        try? FileManager.default.removeItem(atPath: Sparemac.helperApp)
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = ["-c", "sleep 2; /bin/launchctl bootout system/\(Sparemac.helperLabel)"]
        try? task.run()
    }
}

final class Helper: NSObject, HelperProtocol {
    let caller: uid_t
    let callerPID: pid_t
    init(caller: uid_t, callerPID: pid_t) { self.caller = caller; self.callerPID = callerPID }

    /// Runs one command, logging which, who asked and how it ended, never its arguments (a password can be
    /// one), so `log show --predicate 'subsystem == "dev.sparemac.helper"'` lists everything the helper did.
    private func attempt(_ reply: (String?) -> Void, _ function: String = #function, _ body: () throws -> Void) {
        let command = function.prefix { $0 != "(" }
        log("\(command): asked by uid \(caller), pid \(callerPID)")
        do { try body(); log("\(command): done"); reply(nil) } catch { log("\(command): failed: \(error)"); reply("\(error)") }
    }

    func version(reply: @escaping (String) -> Void) {
        reply(team ?? "?")
    }
    func createAccount(_ name: String, fullName: String, password: String, reply: @escaping (String?) -> Void) {
        attempt(reply) { try Ops.createAccount(name, fullName: fullName, password: password) }
    }
    func deleteAccount(_ name: String, reply: @escaping (String?) -> Void) {
        attempt(reply) { try Ops.deleteAccount(name, caller: caller) }
    }
    func signOut(_ name: String, reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.signOut(name) } }
    func removeLeftoverHome(_ name: String, reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.removeLeftoverHome(name) } }
    func installAgent(reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.installAgent(owner: caller, callerPID: callerPID) } }
    func screenSharingState(reply: @escaping (Bool) -> Void) { reply(Ops.screenSharingLoaded()) }
    func applyInputSettings(_ name: String, settings: Data, reply: @escaping (String?) -> Void) {
        attempt(reply) { try Ops.applyInputSettings(name, settings: settings) }
    }
    func setScreenSharing(_ on: Bool, reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.setScreenSharing(on) } }
    func uninstall(reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.uninstall(caller: caller) } }
    func updateHelper(reply: @escaping (String?) -> Void) { attempt(reply) { try Ops.updateHelper(callerPID: callerPID) } }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Only administrators: a copy of Sparemac run from an agent account (Standard) gets nothing.
        let uid = connection.effectiveUserIdentifier
        guard let name = getpwuid(uid).map({ String(cString: $0.pointee.pw_name) }),
              run("/usr/sbin/dseditgroup", ["-o", "checkmember", "-m", name, "admin"]).output.hasPrefix("yes") else {
            log("refused uid \(uid): not an administrator")
            return false
        }
        connection.exportedInterface = NSXPCInterface(with: HelperProtocol.self)
        connection.exportedObject = Helper(caller: uid, callerPID: connection.processIdentifier)
        connection.resume()
        return true
    }
}

guard let team else { log("unsigned helper; refusing to run"); exit(1) }
let listener = NSXPCListener(machServiceName: Sparemac.helperLabel)
// Only Sparemac's own signed app and command, from the same team, may connect.
listener.setConnectionCodeSigningRequirement(
    "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and (identifier \"\(Sparemac.appBundleID)\" or identifier \"dev.sparemac.cli\")")
let delegate = ListenerDelegate()
listener.delegate = delegate
listener.resume()
// Sessions are ordinary, visible macOS users (System Settings › Users & Groups), so anyone can see and check
// them. Older versions hid them; show those too.
for name in Accounts.all() where run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "IsHidden"]).output.contains("1") {
    run("/usr/bin/dscl", [".", "-delete", "/Users/\(name)", "IsHidden"])
    log("showed \(name) in Users & Groups")
}
log("listening as \(Sparemac.helperLabel), team \(team)")
RunLoop.main.run()
