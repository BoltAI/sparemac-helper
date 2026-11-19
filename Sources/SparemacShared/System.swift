import Foundation

/// Names, paths and small system helpers shared by the app, the helper, the command and the agent.
public enum Sparemac {
    public static let appBundleID = "dev.sparemac.app"
    public static let helperLabel = "dev.sparemac.helper"
    public static let agentLabel = "dev.sparemac.agent"
    public static let accountMarker = "Sparemac agent account"
    public static let keychainService = "Sparemac"
    /// The one agent account Sparemac sets up.
    public static let defaultAccount = "agent"

    /// Root-owned: the owner's uid (who Sparemac Tools answers), the socket folders and the optional firewall.
    public static let supportDirectory = "/Library/Application Support/Sparemac"
    public static let ownerFile = "\(supportDirectory)/owner-uid"
    /// Sparemac Tools' bundle: its file name is the name Privacy & Security lists it by.
    public static let agentBundleName = "Sparemac Tools.app"
    public static let agentLaunchAgent = "/Library/LaunchAgents/\(agentLabel).plist"
    /// Sparemac Tools inside an app bundle.
    public static func agentApp(in app: URL) -> URL { app.appendingPathComponent("Contents/Resources/\(agentBundleName)") }
    /// Where sessions run Sparemac Tools from: a copy outside Sparemac.app (macOS would grant its permissions to
    /// Sparemac itself, the app around it, which runs in your account), in a folder you own, so Sparemac keeps it
    /// up to date with no password. Sessions can read it, not change it.
    public static let agentToolsDirectory = "/Users/Shared/Sparemac/Tools"
    public static let agentApp = "\(agentToolsDirectory)/\(agentBundleName)"
    public static let agentExecutable = "\(agentApp)/Contents/MacOS/SparemacAgent"

    /// The admin tool: run only after you type your password, for that one change, then it exits. An app
    /// bundle, so it's signed with an identifier like the rest of Sparemac.
    public static let adminToolName = "Sparemac Helper.app"
    public static let adminToolIdentifier = helperLabel

    /// The optional firewall keeping sessions off your local network: Apple's pfctl, started at every startup by
    /// a launch daemon, with rules that list the sessions. No Sparemac code runs for it.
    public static let firewallLabel = "dev.sparemac.firewall"
    public static let firewallPlist = "/Library/LaunchDaemons/\(firewallLabel).plist"
    public static let firewallScript = "\(supportDirectory)/firewall.sh"
    public static let firewallRules = "\(supportDirectory)/firewall.rules"
    /// Which rules are on (root-owned, so only the admin tool changes them): sessions off the local network, and
    /// Screen Sharing answering only this Mac.
    public static let firewallSessionsMarker = "\(supportDirectory)/firewall-sessions"
    public static let firewallScreenSharingMarker = "\(supportDirectory)/firewall-screen-sharing"

    /// What earlier versions installed, removed by install and uninstall: the helper that ran as root all the
    /// time, and Sparemac Tools copied out of the app.
    public enum Legacy {
        public static let helperApp = "/Library/PrivilegedHelperTools/Sparemac Helper.app"
        public static let helperPlist = "/Library/LaunchDaemons/dev.sparemac.helper.plist"
        public static let agentApp = "/Library/Application Support/Sparemac/Sparemac Tools.app"
        public static let oldAgentApp = "/Library/Application Support/Sparemac/SparemacAgent.app"
    }

    /// The app's own socket, which the command and MCP server use (same user only).
    public static var appSocketPath: String {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Sparemac")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("app.sock").path
    }
}

public struct Failure: Error, CustomStringConvertible, LocalizedError {
    public let description: String
    public init(_ description: String) { self.description = description }
    public var errorDescription: String? { description }
}

/// Runs a program and returns its exit status and output (stdout and stderr together unless `split`).
@discardableResult
public func run(_ path: String, _ arguments: [String], input: String? = nil) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    let inPipe = Pipe()
    if input != nil { process.standardInput = inPipe } else { process.standardInput = FileHandle.nullDevice }
    do { try process.run() } catch { return (-1, "\(error)") }
    if let input {
        inPipe.fileHandleForWriting.write(Data(input.utf8))
        try? inPipe.fileHandleForWriting.close()
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: data, as: UTF8.self))
}

/// Agent accounts and GUI sessions, read without privileges.
public enum Accounts {
    /// Accounts created by Sparemac (they carry the marker in their Comment).
    public static func all() -> [String] {
        run("/usr/bin/dscl", [".", "-list", "/Users", "Comment"]).output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2, parts[1].contains(Sparemac.accountMarker) else { return nil }
            return String(parts[0])
        }.sorted()
    }

    /// The agent account Sparemac uses: the one picked in setup (`saved`, from the app's settings), else
    /// the one older versions made ("sparemac"), else the default name, else any agent account.
    /// The app passes its own setting; the command reads it from the app's preferences.
    public static func preferred(saved: String? = UserDefaults(suiteName: Sparemac.appBundleID)?.string(forKey: "account")) -> String {
        let all = all()
        if let saved, all.contains(saved) { return saved }
        for name in ["sparemac", Sparemac.defaultAccount] where all.contains(name) { return name }
        return all.first ?? Sparemac.defaultAccount
    }

    public static func isAgentAccount(_ name: String) -> Bool {
        run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "Comment"]).output.contains(Sparemac.accountMarker)
    }

    public struct Session {
        public let user: String
        public let onConsole: Bool
    }

    /// GUI sessions on this Mac, from the window server's own list.
    public static func sessions() -> [Session] {
        let data = Data(run("/usr/sbin/ioreg", ["-n", "Root", "-d1", "-a"]).output.utf8)
        guard let root = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let users = root["IOConsoleUsers"] as? [[String: Any]] else { return [] }
        return users.compactMap { entry in
            guard let name = entry["kCGSSessionUserNameKey"] as? String else { return nil }
            return Session(user: name, onConsole: entry["kCGSSessionOnConsoleKey"] as? Bool ?? false)
        }
    }

    public static func hasSession(_ user: String) -> Bool { sessions().contains { $0.user == user } }

    /// Names of the processes an account is running (just the executable names).
    public static func processes(of user: String) -> [String] {
        run("/bin/ps", ["-U", user, "-o", "comm="]).output.split(separator: "\n").map {
            String($0.split(separator: "/").last ?? "")
        }
    }

    public static func uid(of user: String) -> uid_t? { getpwnam(user).map { $0.pointee.pw_uid } }

    /// The full name macOS gets for a session: "Session 2" shows as "Sparemac Session 2" in Users & Groups,
    /// so it's clear whose account it is.
    public static func fullName(for name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix("Session ") ? "Sparemac " + trimmed : trimmed
    }

    /// Whether an account already has this full name: macOS refuses to create a second one.
    public static func fullNameTaken(_ fullName: String) -> Bool {
        let wanted = fullName.lowercased()
        setpwent()
        defer { endpwent() }
        while let entry = getpwent() {
            if let gecos = entry.pointee.pw_gecos, String(cString: gecos).lowercased() == wanted { return true }
        }
        return false
    }
}

/// Talks to the in-account agent of an account.
public enum Agent {
    /// Sends one request and returns the reply, or throws the agent's error.
    public static func call(_ account: String, _ request: [String: Any]) throws -> [String: Any] {
        guard Accounts.hasSession(account) else { throw Failure("\(account) is signed out") }
        guard let line = Wire.connect(to: account) else { throw Failure("Sparemac Tools isn't running in \(account) yet") }
        guard let reply = line.call(request) else { throw Failure("no reply from \(account)") }
        guard reply["ok"] as? Bool == true else { throw Failure(reply["error"] as? String ?? "failed") }
        return reply
    }
}

/// The command and MCP server reach the app through this socket.
public enum AppLink {
    public static func call(_ request: [String: Any]) -> [String: Any]? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        guard withUnixAddress(Sparemac.appSocketPath, { Darwin.connect(fd, $0, $1) }) == 0 else { close(fd); return nil }
        return Line(fd).call(request)
    }
}

/// The sessions' copy of Sparemac Tools: each build in a folder of its own under .builds, and "Sparemac Tools.app"
/// a link to the current one. A Tools still running keeps its own folder, so its signature (which Sparemac checks
/// before it talks to it) still matches its files until it restarts on the new build.
public enum ToolsCopy {
    public static var builds: String { "\(Sparemac.agentToolsDirectory)/.builds" }

    /// A bundle's build number, read from its Info.plist each time (Bundle keeps the first one it read).
    public static func build(of bundle: String) -> String? {
        NSDictionary(contentsOfFile: bundle + "/Contents/Info.plist")?["CFBundleVersion"] as? String
    }

    /// Copies `source` in when this build isn't there yet, and points the link at it. Answers whether the link
    /// moved. `folder` makes a folder it may write in (the admin tool checks who owns it); `staging` is where a
    /// copy is made before it's moved into place, and `ready` checks and hands over a staged copy.
    public static func place(_ source: String, folder: (String) throws -> Void = { try FileManager.default.createDirectory(atPath: $0, withIntermediateDirectories: true) },
                             staging: String? = nil, ready: (String) throws -> Void = { _ in }) throws -> Bool {
        guard let build = build(of: source), !build.isEmpty, build.allSatisfy(\.isNumber) else { throw Failure("Sparemac Tools has no build number") }
        let fm = FileManager.default
        let name = Sparemac.agentBundleName, link = Sparemac.agentApp
        let relative = ".builds/\(build)/\(name)"
        if (try? fm.destinationOfSymbolicLink(atPath: link)) == relative, fm.fileExists(atPath: "\(builds)/\(build)/\(name)") { return false }
        try folder(Sparemac.agentToolsDirectory)
        try folder(builds)
        prune(keeping: build)
        let target = "\(builds)/\(build)"
        if !fm.fileExists(atPath: "\(target)/\(name)") {
            let stage = staging ?? "\(builds)/.staging-\(UUID().uuidString.prefix(8))"
            try fm.createDirectory(atPath: stage, withIntermediateDirectories: true)
            defer { try? fm.removeItem(atPath: stage) }
            guard run("/usr/bin/ditto", [source, "\(stage)/\(name)"]).status == 0 else { throw Failure("couldn't copy Sparemac Tools") }
            try ready("\(stage)/\(name)")
            try? fm.removeItem(atPath: target)
            try folder(target)
            guard rename("\(stage)/\(name)", "\(target)/\(name)") == 0 else { throw Failure("couldn't put Sparemac Tools in place") }
        }
        // A folder from before builds had folders of their own goes aside: a link can't take a folder's place.
        if (try? fm.attributesOfItem(atPath: link))?[.type] as? FileAttributeType == .typeDirectory {
            try? fm.moveItem(atPath: link, toPath: "\(builds)/.old-\(UUID().uuidString.prefix(8))")
        }
        let temp = "\(Sparemac.agentToolsDirectory)/.link-\(UUID().uuidString.prefix(8))"
        try fm.createSymbolicLink(atPath: temp, withDestinationPath: relative)
        guard rename(temp, link) == 0 else { try? fm.removeItem(atPath: temp); throw Failure("couldn't switch Sparemac Tools to build \(build)") }
        return true
    }

    /// Keeps `current` and the newest build before it (a session may run it until it restarts); the rest goes.
    static func prune(keeping current: String) {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: builds)) ?? []
        let older = names.filter { $0.allSatisfy(\.isNumber) && $0 != current }.sorted().dropLast(1)
        for name in Array(older) + names.filter({ $0.hasPrefix(".old-") || $0.hasPrefix(".staging-") }) {
            try? FileManager.default.removeItem(atPath: "\(builds)/\(name)")
        }
    }
}
