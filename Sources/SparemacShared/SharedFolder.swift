import Foundation

/// A folder both you and an agent account can read and write, for getting builds in and results out.
/// The agent account can't open your home folder, and files you put in /Users/Shared are read-only to
/// it (they belong to you and your group), so this folder carries access-control entries for both
/// accounts that every file and folder inside inherits.
public enum SharedFolder {
    public static let parent = "/Users/Shared/Sparemac/files"

    public static func path(for account: String) -> String { "\(parent)/\(account)" }

    /// Single-quoted for a shell.
    public static func quoted(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// A path for the agent account's shell, where a leading ~ means its home folder.
    public static func agentShellPath(_ path: String) -> String {
        if path == "~" { return "\"$HOME\"" }
        if path.hasPrefix("~/") { return "\"$HOME\"/" + quoted(String(path.dropFirst(2))) }
        return quoted(path)
    }

    /// Creates the account's folder if needed (run as you, the owner) and returns its path.
    @discardableResult
    public static func ensure(_ account: String) throws -> String {
        guard getpwnam(account) != nil else { throw Failure("\(account) is not an account on this Mac") }
        let fm = FileManager.default
        let folder = path(for: account)
        if !fm.fileExists(atPath: parent) {
            try fm.createDirectory(atPath: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        }
        if !fm.fileExists(atPath: folder) {
            try fm.createDirectory(atPath: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        let owner = (try? fm.attributesOfItem(atPath: folder))?[.ownerAccountID] as? NSNumber
        guard owner?.uint32Value == getuid() else { throw Failure("\(folder) belongs to another account; remove it, then try again") }
        // Only you and the agent account: full access, inherited by everything inside.
        if !run("/bin/ls", ["-lde", folder]).output.contains("user:\(account) allow") {
            let me = NSUserName()
            for user in [account, me] {
                let ace = "user:\(user) allow read,write,append,execute,delete,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit"
                let result = run("/bin/chmod", ["+a", ace, folder])
                guard result.status == 0 else { throw Failure("couldn't share \(folder): \(result.output)") }
            }
        }
        return folder
    }

    /// Your path with a leading ~ expanded to your home folder.
    public static func ownerPath(_ path: String) -> String { (path as NSString).expandingTildeInPath }

    /// Copies a file or folder (an app bundle too) without its own access-control lists, so the copy
    /// takes the folder's.
    public static func copy(_ from: String, _ to: String) throws {
        let result = run("/usr/bin/ditto", ["--noacl", from, to])
        guard result.status == 0 else { throw Failure("copying \(from) failed: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))") }
    }
}
