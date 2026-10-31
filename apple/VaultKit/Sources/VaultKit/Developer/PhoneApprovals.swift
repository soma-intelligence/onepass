import Foundation
import Observation
import OnePassCore
import os

/// The "iPhone" card of Réglages > Développeur on the Mac (agent-ready spec 7): the phones in the
/// signed approver list, "Approuver aussi sur l'iPhone" (the panel races them), "Déverrouiller depuis
/// mon iPhone" (`RemoteUnlockCoordinator.enroll`, Touch ID first) and the agents' window length.
///
/// It owns the app's `RemoteUnlockCoordinator` (nil without CloudKit: unsigned builds, demo data, UI
/// tests). Every call waits for `start()` first, so the coordinator reads its enrollment and erases
/// the expired records before any refresh, forget or gate use. The full-unlock approver is built by
/// the coordinator on its own mailbox: one reader of this Mac's messages.
@MainActor
@Observable
public final class PhoneApprovals {
    public struct Phone: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String

        public init(id: String, name: String) {
            self.id = id
            self.name = name
        }
    }

    /// The window lengths offered (spec 6.3: 15 min to 8 h, 1 h by default).
    public static let windowChoices = [15, 30, 60, 120, 240, 480]

    /// The phones of the signed approver list (revoked devices are left out by the core).
    public private(set) var phones: [Phone] = []
    /// The two letters the phone shows too, after an enrollment.
    public private(set) var pairingCode: String?
    /// The last failure of an action of the card.
    public private(set) var errorMessage: String?
    /// An enrollment or a forget is running.
    public private(set) var busy = false

    public let coordinator: RemoteUnlockCoordinator?
    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let hosts: DeveloperHosts
    @ObservationIgnored private var started: Task<Void, Never>?
    /// The refresh in flight: refreshes run one after the other, never interleaved.
    @ObservationIgnored private var wiring: Task<Void, Never>?
    #if DEBUG
    private var demoUnlockPhone: String??
    #endif
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    public init(vault: VaultSession, hosts: DeveloperHosts, coordinator: RemoteUnlockCoordinator?) {
        self.vault = vault
        self.hosts = hosts
        self.coordinator = coordinator
    }

    /// CloudKit is there: the iPhone can approve and unlock.
    public var available: Bool {
        #if DEBUG
        if demoUnlockPhone != nil { return true }
        #endif
        return coordinator != nil
    }

    public var approveOnPhone: Bool { hosts.settings.approveOnPhone }
    public var windowMinutes: Int { hosts.settings.agentWindowMinutes }

    /// The phone whose remote unlock is enrolled here, nil when off.
    public var unlockPhone: String? {
        #if DEBUG
        if let demoUnlockPhone { return demoUnlockPhone }
        #endif
        return coordinator?.enrolledPhone
    }

    /// Why the last remote unlock did not open, for the card.
    public var lastFailure: String? { coordinator?.lastFailure?.message }

    // MARK: - Lifecycle

    /// At launch, once: the coordinator reads its enrollment and erases what expired.
    public func start() async {
        if started == nil {
            let coordinator = self.coordinator
            started = Task { await coordinator?.start() }
        }
        await started?.value
    }

    /// After an unlock: the phones are read again and the panel races them.
    public func sessionUnlocked() async {
        await refreshAndWire()
    }

    /// Reads the phones and sets (or clears) the iPhone approver of the next approvals.
    public func refreshAndWire() async {
        let previous = wiring
        let task = Task { [weak self] in
            await previous?.value
            guard let self else { return }
            await self.start()
            await self.refresh()
            await self.wire()
        }
        wiring = task
        await task.value
        if wiring == task { wiring = nil }
    }

    private func refresh() async {
        #if DEBUG
        if demoUnlockPhone != nil { return }
        #endif
        guard coordinator != nil, vault.state == .unlocked,
            let list = try? await vault.read({ try $0.approvers() })
        else {
            if vault.state == .unlocked { phones = [] }
            return
        }
        phones = list.filter { $0.role == .phone }.map { Phone(id: $0.deviceId, name: $0.deviceName) }
        hosts.setPhoneNames(Dictionary(phones.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a }))
    }

    /// Setting on and CloudKit there: the full-unlock approver, on the coordinator's mailbox. With
    /// no phone listed it still runs, so the panel says "iPhone indisponible : approuve ici" (spec
    /// 5.3). The Mac's approval keys join the signed list once a phone exists to trust them.
    private func wire() async {
        guard let coordinator, approveOnPhone, vault.state == .unlocked else {
            hosts.useRemoteApprover(nil)
            return
        }
        do {
            hosts.useRemoteApprover(try await coordinator.makeApprover(register: !phones.isEmpty))
        } catch {
            hosts.useRemoteApprover(nil)
            Self.log.error("iPhone approver not set")
        }
    }

    // MARK: - Actions

    /// "Approuver aussi sur l'iPhone".
    public func setApproveOnPhone(_ on: Bool) async {
        await hosts.update({ $0.approveOnPhone = on }, session: vault)
        await refreshAndWire()
    }

    /// "Déverrouiller depuis mon iPhone": on enrolls `phone` (the first listed by default), Touch ID
    /// first; off forgets it on this Mac.
    public func setUnlockFromPhone(_ on: Bool, phone: String? = nil) async {
        await start()
        guard let coordinator, !busy else { return }
        busy = true
        defer { busy = false }
        if on {
            guard let target = phone ?? phones.first?.id else {
                errorMessage = String(localized: "Aucun iPhone enrôlé.", bundle: VaultKitStrings.bundle)
                return
            }
            do {
                pairingCode = try await coordinator.enroll(phone: target)
                errorMessage = nil
            } catch {
                pairingCode = nil
                errorMessage = VaultError(error).localizedMessage
            }
        } else if let enrolled = coordinator.enrolledPhone {
            await coordinator.forget(phone: enrolled)
            pairingCode = nil
            errorMessage = nil
        }
    }

    /// The agents' window length, clamped to 15 min to 8 h.
    public func setWindowMinutes(_ minutes: Int) async {
        await hosts.update({ $0.agentWindowMinutes = minutes }, session: vault)
    }

    #if DEBUG
    /// Screenshots: fictional phones, without CloudKit.
    public func showDemo(phones: [Phone], unlockPhone: String?) {
        self.phones = phones
        demoUnlockPhone = .some(unlockPhone)
        hosts.setPhoneNames(Dictionary(phones.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a }))
    }
    #endif
}
