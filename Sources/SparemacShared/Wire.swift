import Foundation
import Security

/// Where the in-account agents listen, and how messages travel: one JSON object per line.
public enum Wire {
    /// Root-owned; each session has a folder of its own inside, which only that session can write to, so no
    /// account can take another's socket.
    public static let runDirectory = "/Library/Application Support/Sparemac/run"
    public static func folder(for user: String) -> String { "\(runDirectory)/\(user)" }
    public static func socketPath(for user: String) -> String { "\(folder(for: user))/tools.sock" }

    /// Connects to an agent account's socket. Returns nil if nothing is listening, or if what's listening isn't
    /// that account's own Sparemac Tools: nothing (a password above all) goes to anything else.
    public static func connect(to user: String) -> Line? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let ok = withUnixAddress(socketPath(for: user)) { Darwin.connect(fd, $0, $1) } == 0
        guard ok, peerIsTools(fd, of: user) else { close(fd); return nil }
        return Line(fd)
    }

    /// Asks the session's Sparemac Tools to restart, without checking its signature: for a Tools whose files
    /// changed under it, whose signature no longer checks out. A restart carries nothing a stranger could use.
    @discardableResult
    public static func restartUnchecked(_ user: String) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        var uid: uid_t = 0, gid: gid_t = 0
        guard withUnixAddress(socketPath(for: user), { Darwin.connect(fd, $0, $1) }) == 0,
              getpeereid(fd, &uid, &gid) == 0, uid == Accounts.uid(of: user) else { close(fd); return false }
        return Line(fd).call(["cmd": "restart", "origin": "user"]) != nil
    }

    /// The process at the other end runs as `user` and is Sparemac Tools, signed by the same team as this one.
    static func peerIsTools(_ fd: Int32, of user: String) -> Bool {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, let expected = Accounts.uid(of: user), uid == expected else { return false }
        guard ownTeam != nil, let requirement = toolsRequirement else { return true }  // an unsigned build of our own, while developing
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, 6 /* LOCAL_PEERTOKEN */, &token, &length) == 0 else { return false }
        // A process that passed once keeps passing: the app connects every 2 s, and checking the signature each time
        // cost steady CPU. Keyed by pid and pid version (val[5], val[7]), so another process given the same pid is
        // checked again.
        let key = UInt64(UInt32(bitPattern: Int32(token.val.5))) << 32 | UInt64(token.val.7)
        if verifiedLock.withLock({ verified.contains(key) }) { return true }
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return false }
        verifiedLock.withLock { if verified.count > 64 { verified.removeAll() }; verified.insert(key) }
        return true
    }

    /// Sparemac Tools signed by this program's team, made once.
    nonisolated(unsafe) static let toolsRequirement: SecRequirement? = {
        guard let team = ownTeam else { return nil }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(Sparemac.agentLabel)\"" as CFString, [], &requirement) == errSecSuccess else { return nil }
        return requirement
    }()
    nonisolated(unsafe) private static var verified = Set<UInt64>()
    private static let verifiedLock = NSLock()

    /// The team that signed this program, read from its own signature once.
    static let ownTeam: String? = {
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }()
}

/// Calls `body` with a sockaddr_un for `path`.
public func withUnixAddress<T>(_ path: String, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8)
    precondition(bytes.count < MemoryLayout.size(ofValue: address.sun_path), "socket path too long")
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
    return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
}

/// A socket that sends and receives JSON objects, one per line.
public final class Line {
    public let fd: Int32
    private var pending = Data()
    /// How far `pending` has been searched for a newline, so a large reply (a full-screen screenshot is
    /// ~10 MB) isn't searched again from the start after every read.
    private var searched = 0

    public init(_ fd: Int32) { self.fd = fd }
    deinit { close(fd) }

    /// Reads give up (and `receive` answers nil) after this many seconds without data; nil waits for ever.
    public func setReadTimeout(_ seconds: Double?) {
        let whole = Int(seconds ?? 0)
        var limit = timeval(tv_sec: whole, tv_usec: Int32(((seconds ?? 0) - Double(whole)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
    }

    public func receive() -> [String: Any]? {
        while true {
            let newline = pending.withUnsafeBytes { raw -> Int? in
                guard searched < raw.count, let base = raw.baseAddress,
                      let hit = memchr(base + searched, 0x0A, raw.count - searched) else { return nil }
                return base.distance(to: UnsafeRawPointer(hit))
            }
            if let end = newline {
                let line = pending.prefix(end)
                pending = Data(pending.dropFirst(end + 1)); searched = 0
                return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any]
            }
            searched = pending.count
            var chunk = [UInt8](repeating: 0, count: 65536)
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { return nil }
            pending.append(contentsOf: chunk[0..<n])
        }
    }

    @discardableResult
    public func send(_ message: [String: Any]) -> Bool {
        guard var data = try? JSONSerialization.data(withJSONObject: message) else { return false }
        data.append(0x0A)
        return data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }

    /// Binary frames for the screen stream: a JSON header line with "bytes", then that many raw bytes.
    @discardableResult
    public func send(_ header: [String: Any], payload: Data) -> Bool {
        var header = header
        header["bytes"] = payload.count
        return send(header) && payload.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }

    /// Reads a header line and, when it announces "bytes", the payload after it.
    public func receiveFrame() -> (header: [String: Any], payload: Data)? {
        guard let header = receive() else { return nil }
        let count = header["bytes"] as? Int ?? 0
        while pending.count < count {
            var chunk = [UInt8](repeating: 0, count: max(65536, count - pending.count))
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { return nil }
            pending.append(contentsOf: chunk[0..<n])
        }
        let payload = Data(pending.prefix(count))
        pending.removeFirst(count); searched = 0
        return (header, payload)
    }

    /// Ends a blocking receive from another thread.
    public func shutdown() { Darwin.shutdown(fd, SHUT_RDWR) }

    /// Sends a request and waits for its reply.
    public func call(_ request: [String: Any]) -> [String: Any]? {
        guard send(request) else { return nil }
        return receive()
    }
}
