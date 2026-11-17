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

    /// Where the helper installs SparemacAgent for every session (root-owned).
    public static let supportDirectory = "/Library/Application Support/Sparemac"
    public static let ownerFile = "\(supportDirectory)/owner-uid"
    public static let agentLaunchAgent = "/Library/LaunchAgents/\(agentLabel).plist"
    /// The root helper is an app bundle, so it shows by name in Privacy & Security (Full Disk Access).
    public static let helperApp = "/Library/PrivilegedHelperTools/Sparemac Helper.app"
    public static let helperExecutable = "\(helperApp)/Contents/MacOS/SparemacHelper"
    public static let helperPlist = "/Library/LaunchDaemons/\(helperLabel).plist"

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
