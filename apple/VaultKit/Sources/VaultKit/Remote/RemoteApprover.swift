import Foundation
import OnePassCore
import os

/// The core calls the remote approval needs (agent-ready spec 5.1). `Session` is the real one; the
/// tests script it.
public protocol RemoteApprovalSession: Sendable {
    func thisDeviceId() -> String?
    func approvers() throws -> [FfiApprover]
    func sealRemoteRequest(keys: FfiApproverKeys, to: String, kind: FfiRemoteKind, body: FfiRequestBody) throws
        -> FfiSealedRequest
    func openRemoteResponse(keys: FfiApproverKeys, blob: Data) throws -> FfiRemoteResponse
}

extension Session: RemoteApprovalSession {}

/// Mac side of the remote approval (spec 5.3): one sealed request per enrolled phone, then the first
/// valid answer of any of them. A valid answer that comes after the decision (a second phone, a
/// refusal after an approval) is logged `late` and changes nothing.
///
/// It reads the Mac's messages through a `RemoteMailbox` (shared with the remote unlock, so one reader
/// routes every message) while a request waits or may still be answered (until its expiry), and
/// opens each answer once: the core accepts one answer per request. Only the answers it opens are
/// claimed (deleted); anything else is left to the other consumers.
public actor RemoteApprover {
    /// At least one phone got the last request (false: no phone enrolled, or CloudKit unreachable).
    public private(set) var phonesAvailable = false
    /// Device ids of the valid answers that came after the decision, oldest first.
    public private(set) var lateAnswers: [String] = []

    private let channel: any RemoteChannel
    private let session: any RemoteApprovalSession
    private let keys: FfiApproverKeys
    private let timeout: Duration
    private let now: @Sendable () -> Date

    private struct Waiter {
        var continuation: CheckedContinuation<FfiAnswer?, Never>?
        var result: FfiAnswer??
    }

    /// A request this Mac sent, kept until it expires so a late answer is recognized.
    private struct Issued {
        let waiter: UUID
        let phone: String
        let record: String
        let expiresAt: Date
    }

    private var waiters: [UUID: Waiter] = [:]
    private var issued: [Data: Issued] = [:]
    private var mailbox: RemoteMailbox?
    private var subscription: UUID?
    private var stopTimer: Task<Void, Never>?
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    /// `timeout` is the request lifetime of the spec (60 s); the tests pass less. `mailbox`: the
    /// Mac's shared reader (nil: one of its own, made on first use).
    public init(
        channel: any RemoteChannel, session: any RemoteApprovalSession, keys: FfiApproverKeys,
        timeout: Duration = .seconds(60), now: @escaping @Sendable () -> Date = { Date() },
        mailbox: RemoteMailbox? = nil
    ) {
        self.mailbox = mailbox
        self.channel = channel
        self.session = session
        self.keys = keys
        self.timeout = timeout
        self.now = now
    }

    /// Asks every enrolled phone. Nil when no phone got the request (none enrolled, or CloudKit
    /// unreachable), when nobody answered in time, or when the caller cancelled (the Mac answered
    /// first): the requests are then withdrawn.
    public func ask(_ r: FfiApprovalRequest) async -> FfiAnswer? {
        await ask(r, onSent: { _ in })
    }

    /// `ask`, telling `onSent` the names of the phones that got the request.
    public func ask(_ r: FfiApprovalRequest, onSent: @Sendable ([String]) -> Void) async -> FfiAnswer? {
        let session = self.session
        let keys = self.keys
        guard let me = session.thisDeviceId(),
              let approvers = try? await CoreThread.run({ try session.approvers() })
        else {
            phonesAvailable = false
            return nil
        }
        let phones = approvers.filter { $0.role == .phone }
        guard !phones.isEmpty, !Task.isCancelled else {
            phonesAvailable = false
            return nil
        }

        let id = UUID()
        waiters[id] = Waiter()
        await startListening(me)
        let body = Self.body(of: r)
        var sentTo: [String] = []
        for phone in phones where waiters[id]?.result == nil && !Task.isCancelled {
            do {
                let sealed = try await CoreThread.run {
                    try session.sealRemoteRequest(keys: keys, to: phone.deviceId, kind: .approve, body: body)
                }
                let message = RemoteMessage(
                    id: "request-" + Self.hex(sealed.requestId), to: sealed.to, blob: sealed.blob,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt)))
                issued[sealed.requestId] = Issued(
                    waiter: id, phone: phone.deviceId, record: message.id, expiresAt: message.expiresAt)
                do {
                    try await channel.post(message)
                    sentTo.append(phone.deviceName)
                } catch {
                    issued.removeValue(forKey: sealed.requestId)
                    throw error
                }
            } catch {
                Self.log.error("remote request not sent")
            }
        }
        guard !sentTo.isEmpty else {
            phonesAvailable = false
            resolve(id, with: nil)
            return await park(id)
        }
        phonesAvailable = true
        onSent(sentTo)

        let timeout = self.timeout
        let timer = Task { [weak self] in
            do { try await Task.sleep(for: timeout) } catch { return }
            await self?.resolve(id, with: nil)
        }
        let answer = await withTaskCancellationHandler {
            await park(id)
        } onCancel: {
            Task { await self.resolve(id, with: nil) }
        }
        timer.cancel()
        return answer
    }

    /// Erases the records that expired (at launch: nothing stays after a quit or a sleep, spec 5.2).
    public func purgeExpired() async {
        await channel.purgeExpired(now: now())
    }

    // MARK: - Waiting

    private func park(_ id: UUID) async -> FfiAnswer? {
        await withCheckedContinuation { (c: CheckedContinuation<FfiAnswer?, Never>) in
            if let result = waiters[id]?.result {
                waiters.removeValue(forKey: id)
                c.resume(returning: result)
            } else if waiters[id] != nil {
                waiters[id]?.continuation = c
            } else {
                c.resume(returning: nil)
            }
        }
    }

    /// Settles a waiter once (answer, timeout or cancel) and withdraws its requests.
    private func resolve(_ id: UUID, with answer: FfiAnswer?) {
        guard var waiter = waiters[id], waiter.result == nil else { return }
        if let c = waiter.continuation {
            waiters.removeValue(forKey: id)
            c.resume(returning: answer)
        } else {
            waiter.result = .some(answer)
            waiters[id] = waiter
        }
        let records = issued.values.filter { $0.waiter == id }.map(\.record)
        let channel = self.channel
        Task { for record in records { await channel.delete(record) } }
        scheduleStop()
    }

    // MARK: - Listening

    private func startListening(_ me: String) async {
        stopTimer?.cancel()
        stopTimer = nil
        guard subscription == nil else { return }
        let box = mailbox ?? RemoteMailbox(channel: channel, device: me, now: now)
        mailbox = box
        subscription = await box.register(.approval) { [weak self] message in
            await self?.claim(message) ?? false
        }
    }

    private func stopListening() {
        guard let subscription, let mailbox else { return }
        self.subscription = nil
        Task { await mailbox.unregister(subscription) }
    }

    /// True when this approver opened `message` (an answer to one of its requests, on time or late).
    private func claim(_ message: RemoteMessage) async -> Bool {
        let session = self.session
        let keys = self.keys
        let blob = message.blob
        guard let response = try? await CoreThread.run({ try session.openRemoteResponse(keys: keys, blob: blob) })
        else { return false }
        await handle(response)
        return true
    }

    private func handle(_ response: FfiRemoteResponse) async {
        defer { scheduleStop() }
        let entry = issued.removeValue(forKey: response.requestId)
        if let entry {
            // Answered: its request record goes too.
            await channel.delete(entry.record)
        }
        guard let entry, entry.phone == response.from else {
            // Signed by a phone of the list, but not for a request this Mac sent it.
            Self.log.notice("remote answer refused: no request sent to that phone")
            return
        }
        guard let waiter = waiters[entry.waiter], waiter.result == nil else {
            lateAnswers.append(response.from)
            Self.log.notice("late remote answer from \(response.from, privacy: .private) ignored")
            return
        }
        resolve(entry.waiter, with: FfiAnswer(
            decision: Self.decision(response.decision), approvedOn: "phone:\(response.from)"))
    }

    /// Stops the listener once nothing waits and every request sent has expired.
    private func scheduleStop() {
        let current = now()
        issued = issued.filter { $0.value.expiresAt > current }
        guard waiters.values.allSatisfy({ $0.result != nil }) else { return }
        guard let last = issued.values.map(\.expiresAt).max() else {
            stopTimer?.cancel()
            stopTimer = nil
            stopListening()
            return
        }
        guard stopTimer == nil else { return }
        let delay = Duration.milliseconds(Int64(max(0, last.timeIntervalSince(current)) * 1000) + 1)
        stopTimer = Task { [weak self] in
            do { try await Task.sleep(for: delay) } catch { return }
            await self?.stopTimerFired()
        }
    }

    private func stopTimerFired() {
        stopTimer = nil
        scheduleStop()
    }

    // MARK: - Mapping

    static func decision(_ d: FfiRemoteDecision) -> FfiDecision {
        switch d {
        case .denied: .deny
        case .once: .allowOnce
        case .grant5m: .allowForMinutes(minutes: 5)
        }
    }

    /// What the phone shows: the request as the panel shows it, targets as `vault / item / field`.
    static func body(of r: FfiApprovalRequest) -> FfiRequestBody {
        FfiRequestBody(
            client: r.client, clientVerified: r.clientVerified, action: r.action, details: r.details,
            targets: r.targets.map { ([$0.vault, $0.item] + ($0.field.map { [$0] } ?? [])).joined(separator: " / ") },
            rememberAllowed: r.rememberAllowed, strongRequired: r.strongRequired, confirmCode: r.confirmCode,
            windowMinutes: nil)
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
