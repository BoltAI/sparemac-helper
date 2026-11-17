import Foundation

/// Where the in-account agents listen, and how messages travel: one JSON object per line.
public enum Wire {
    public static let runDirectory = "/Users/Shared/Sparemac/run"
    public static func socketPath(for user: String) -> String { "\(runDirectory)/\(user).sock" }

    /// Connects to an agent account's socket. Returns nil if nothing is listening.
    public static func connect(to user: String) -> Line? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let ok = withUnixAddress(socketPath(for: user)) { Darwin.connect(fd, $0, $1) } == 0
        if !ok { close(fd); return nil }
        return Line(fd)
    }
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
