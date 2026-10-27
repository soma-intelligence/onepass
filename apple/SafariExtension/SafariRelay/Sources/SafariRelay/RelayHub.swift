import Foundation

/// A running bridge host: frames go in on `input`, come out on `output`.
public protocol HostProcess: AnyObject, Sendable {
    var input: FileHandle { get }
    var output: FileHandle { get }
    /// Stop the host and close its pipes. Idempotent.
    func terminate()
}

/// Starts one bridge host per connection, as Chrome does for each
/// `connectNative` port.
public protocol HostLauncher: Sendable {
    func launch() throws -> any HostProcess
}

/// Launches an executable with fixed arguments, stdio on pipes. stderr goes
/// to /dev/null (the host keeps its own journal, like under Chrome).
public struct ProcessHostLauncher: HostLauncher {
    public let executable: URL
    public let arguments: [String]

    public init(executable: URL, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }

    public func launch() throws -> any HostProcess {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let toHost = Pipe()
        let fromHost = Pipe()
        process.standardInput = toHost
        process.standardOutput = fromHost
        process.standardError = FileHandle.nullDevice
        try process.run()
        // A host that dies must make our write fail with EPIPE, not kill the
        // extension process with SIGPIPE.
        _ = fcntl(toHost.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
        return SpawnedHost(process: process, input: toHost.fileHandleForWriting, output: fromHost.fileHandleForReading)
    }
}

final class SpawnedHost: HostProcess, @unchecked Sendable {
    private let process: Process
    let input: FileHandle
    let output: FileHandle
    private let lock = NSLock()
    private var done = false

    init(process: Process, input: FileHandle, output: FileHandle) {
        self.process = process
        self.input = input
        self.output = output
    }

    func terminate() {
        lock.lock()
        defer { lock.unlock() }
        guard !done else { return }
        done = true
        // End of stdin first: the host treats it as a clean close.
        try? input.close()
        if process.isRunning { process.terminate() }
    }
}

/// One extension connection: a host process and the frames it sent that the
/// extension has not polled yet.
final class Connection: @unchecked Sendable {
    /// More undelivered frames than this: the host is misbehaving, close.
    static let maxQueued = 64

    let host: any HostProcess
    let cond = NSCondition()
    private(set) var frames: [String] = []
    private(set) var ended = false
    var polling = false
    var lastUse: UInt64

    init(host: any HostProcess, now: UInt64) {
        self.host = host
        self.lastUse = now
    }

    /// Read the host's frames on a dedicated thread until it ends.
    func startReader() {
        let thread = Thread { [self] in
            while true {
                let next: Data?
                do {
                    next = try Framing.read(from: host.output)
                } catch {
                    end()
                    return
                }
                // Clean end of stream, or a frame that is not UTF-8 text.
                guard let frame = next, let text = String(data: frame, encoding: .utf8) else {
                    end()
                    return
                }
                cond.lock()
                if ended {
                    cond.unlock()
                    return
                }
                frames.append(text)
                let overflow = frames.count > Self.maxQueued
                cond.broadcast()
                cond.unlock()
                if overflow {
                    end()
                    return
                }
            }
        }
        thread.name = "OnePass bridge relay reader"
        thread.start()
    }

    /// Mark the connection over and wake a waiting poll. Idempotent.
    func end() {
        cond.lock()
        ended = true
        cond.broadcast()
        cond.unlock()
        host.terminate()
    }

    /// Wait until a frame is queued, the host ends, or `deadline`; then take
    /// every queued frame. `nil` when another poll is already waiting.
    func poll(until deadline: Date) -> (frames: [String], ended: Bool)? {
        cond.lock()
        defer { cond.unlock() }
        guard !polling else { return nil }
        polling = true
        while frames.isEmpty && !ended {
            if !cond.wait(until: deadline) { break }
        }
        polling = false
        let out = frames
        frames.removeAll()
        return (out, ended)
    }
}

/// The connections of the Safari extension, keyed by the id the extension
/// drew. Safari delivers each `sendNativeMessage` as a separate request, so
/// the relay keeps the host process (and therefore the bridge session state,
/// held by the host) alive between requests.
public final class RelayHub: @unchecked Sendable {
    private let launcher: (any HostLauncher)?
    private let pollTimeout: TimeInterval
    private let maxConnections: Int
    private let lock = NSLock()
    private var conns: [String: Connection] = [:]
    private var clock: UInt64 = 0

    /// `launcher` nil: this build has no bridge host, every `open` answers
    /// `unavailable`.
    public init(launcher: (any HostLauncher)?, pollTimeout: TimeInterval = 20, maxConnections: Int = 4) {
        self.launcher = launcher
        self.pollTimeout = pollTimeout
        self.maxConnections = maxConnections
    }

    /// Number of open connections (tests).
    public var openConnections: Int {
        lock.lock()
        defer { lock.unlock() }
        return conns.count
    }

    /// Serve one request. Blocks for at most the poll timeout: call it off
    /// the main thread.
    public func handle(_ request: RelayRequest) -> RelayResponse {
        switch request.op {
        case .open: return open(request.conn)
        case .send(let frame): return send(request.conn, frame)
        case .poll: return poll(request.conn)
        case .close:
            if let c = take(request.conn) { c.end() }
            return .ok(frames: [], closed: true)
        }
    }

    /// Parse and serve the raw message of a Safari request.
    public func handle(message: Any?) -> RelayResponse {
        do {
            return handle(try RelayRequest.parse(message))
        } catch {
            return .failure(error)
        }
    }

    private func open(_ id: String) -> RelayResponse {
        guard let launcher else { return .failure(.unavailable) }
        lock.lock()
        if conns[id] != nil {
            lock.unlock()
            return .failure(.exists)
        }
        lock.unlock()
        let host: any HostProcess
        do {
            host = try launcher.launch()
        } catch {
            return .failure(.unavailable)
        }
        lock.lock()
        clock += 1
        let conn = Connection(host: host, now: clock)
        var evicted: [Connection] = []
        if conns[id] != nil {
            lock.unlock()
            host.terminate()
            return .failure(.exists)
        }
        while conns.count >= maxConnections,
            let oldest = conns.min(by: { $0.value.lastUse < $1.value.lastUse })
        {
            conns[oldest.key] = nil
            evicted.append(oldest.value)
        }
        conns[id] = conn
        lock.unlock()
        for c in evicted { c.end() }
        conn.startReader()
        return .ok(frames: [], closed: false)
    }

    private func send(_ id: String, _ frame: Data) -> RelayResponse {
        guard let conn = touch(id) else { return .failure(.unknownConn) }
        let bytes: Data
        do {
            bytes = try Framing.encode(frame)
        } catch {
            return .failure(error)
        }
        do {
            try conn.host.input.write(contentsOf: bytes)
        } catch {
            _ = take(id)
            conn.end()
            return .failure(.transport)
        }
        return .ok(frames: [], closed: false)
    }

    private func poll(_ id: String) -> RelayResponse {
        guard let conn = touch(id) else { return .failure(.unknownConn) }
        guard let (frames, ended) = conn.poll(until: Date().addingTimeInterval(pollTimeout)) else {
            return .failure(.busy)
        }
        if ended {
            lock.lock()
            if conns[id] === conn { conns[id] = nil }
            lock.unlock()
        }
        return .ok(frames: frames, closed: ended)
    }

    private func touch(_ id: String) -> Connection? {
        lock.lock()
        defer { lock.unlock() }
        guard let c = conns[id] else { return nil }
        clock += 1
        c.lastUse = clock
        return c
    }

    private func take(_ id: String) -> Connection? {
        lock.lock()
        defer { lock.unlock() }
        return conns.removeValue(forKey: id)
    }
}
