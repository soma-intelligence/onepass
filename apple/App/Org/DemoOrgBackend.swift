#if DEBUG
import Foundation
import VaultKit

/// `-OnePassDemoOrg` (Debug screenshots): a made-up organisation "Atelier Atlas" held in memory, no
/// server and no `TestOrgServer`. Its changes only edit the in-memory roster; it signs nothing.
/// `YES`: the demo account is an Owner with members and one join request. `join`: the demo account is
/// a member whose join request waits for its administrator.
actor DemoOrgBackend: OrgBackend {
    private var current: FfiOrgState
    private var requests: [FfiJoinRequest]

    init(me accountID: String, joining: Bool) {
        current = Self.state(me: accountID, joining: joining)
        requests = joining ? [] : [Self.request]
    }

    func state() async throws -> FfiOrgState? { current }
    func pin(source: FfiPinSource, expected: Data?, now: Int64) async throws -> FfiOrgState { current }
    func refresh() async throws -> FfiOrgState { current }

    func markVerified() async throws -> FfiOrgState {
        current.source = .tofu(verified: true)
        return current
    }

    func joinRequests() async throws -> [FfiJoinRequest] { requests }

    func postJoinRequest(
        session: Session, keys: DeviceKeyPair, invite: FfiOrgInvite, displayName: String, credentialSeed: Data,
        now: Int64
    ) async throws -> FfiJoinPosted {
        FfiJoinPosted(codeWords: Self.joinCode)
    }

    func revokeOwnCredential() async throws {}

    func declineJoinRequest(accountID: String) async throws {
        requests.removeAll { $0.accountId == accountID }
    }

    func summarize(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit) async throws -> FfiEditSummary {
        let (id, after) = Self.target(of: edit)
        let request = requests.first { $0.accountId == id }
        let member = current.members.first { $0.accountId == id }
        let rolesBefore = member?.roles ?? []
        return FfiEditSummary(
            memberName: member?.displayName ?? request?.displayName ?? id,
            deviceCount: UInt32(request?.devices.count ?? member?.devices.count ?? 0),
            rolesBefore: rolesBefore, rolesAfter: after.roles ?? rolesBefore, stateBefore: member?.state,
            stateAfter: after.state ?? member?.state ?? .active, allowed: true)
    }

    func edit(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit, now: Int64) async throws -> FfiEditOutcome {
        let (id, after) = Self.target(of: edit)
        if let request = requests.first(where: { $0.accountId == id }) {
            requests.removeAll { $0.accountId == id }
            current.members.removeAll { $0.accountId == id }
            current.members.append(FfiOrgMember(
                accountId: id, displayName: request.displayName, roles: after.roles ?? [], state: .active,
                devices: request.devices, formerOwner: false))
        } else if let index = current.members.firstIndex(where: { $0.accountId == id }) {
            if let roles = after.roles { current.members[index].roles = roles }
            if case .removed = after.state {
                current.members[index].state = .removed(at: now, by: current.owners.first ?? "")
            } else if let state = after.state {
                current.members[index].state = state
            }
        }
        current.rosterSeq += 1
        return FfiEditOutcome(state: current, serverAccessUpdated: true)
    }

    func createInvite(
        session: Session, keys: DeviceKeyPair, label: String, domain: String?, roles: [FfiOrgRole], now: Int64
    ) async throws -> FfiInviteLink {
        let id = String(repeating: "7", count: 32)
        current.members.append(FfiOrgMember(
            accountId: id, displayName: label, roles: roles, state: .invited, devices: [], formerOwner: false))
        current.rosterSeq += 1
        let link = "onepass://org/join?v=1&s=https%3A%2F%2Forg.atlas.exemple.fr&m=\(String(repeating: "a", count: 32))"
            + "&o=\(current.orgId)&a=\(id)&d=\(domain ?? "atlas.exemple.fr")"
        return FfiInviteLink(link: link, accountId: id)
    }

    func ownerKeysAvailable(session: Session, keys: DeviceKeyPair) async throws -> Bool { true }

    func setOwners(session: Session, keys: DeviceKeyPair, owners: [String], now: Int64) async throws -> FfiOrgState {
        current.owners = owners
        for index in current.members.indices where owners.contains(current.members[index].accountId) {
            if !current.members[index].roles.contains(.owner) { current.members[index].roles.append(.owner) }
        }
        current.lineageGeneration += 1
        return current
    }

    // MARK: - Fixed data

    private static let joinCode = ["harbor", "velvet", "simmer", "outfit", "lagoon"]

    private static let request = FfiJoinRequest(
        accountId: String(repeating: "5", count: 32), displayName: "Noah Petit",
        devices: [FfiOrgDevice(fingerprint: hex("9f3a"), name: "iPhone de Noah")],
        codeWords: ["maple", "drift", "copper", "lantern", "quiver"], issuedHere: true,
        inviteLabel: "Noah, design", inRoster: false)

    /// What an edit does to its member: (account id, roles after, state after).
    private static func target(of edit: FfiRosterEdit) -> (String, (roles: [FfiOrgRole]?, state: FfiMemberState?)) {
        switch edit {
        case .accept(let id, let roles): (id, (roles, .active))
        case .setRoles(let id, let roles): (id, (roles, nil))
        case .suspend(let id): (id, (nil, .suspended))
        case .reactivate(let id): (id, (nil, .active))
        case .remove(let id): (id, (nil, .removed(at: 0, by: "")))
        }
    }

    private static func hex(_ seed: String) -> String {
        String(String(repeating: seed, count: 16).prefix(64))
    }

    private static func state(me: String, joining: Bool) -> FfiOrgState {
        let owner = joining ? String(repeating: "1", count: 32) : me
        var members = [
            FfiOrgMember(
                accountId: String(repeating: "2", count: 32), displayName: "Léo Martin", roles: [.admin], state: .active,
                devices: [
                    FfiOrgDevice(fingerprint: hex("4b2e"), name: "MacBook de Léo"),
                    FfiOrgDevice(fingerprint: hex("c071"), name: "iPhone de Léo"),
                ],
                formerOwner: true),
            FfiOrgMember(
                accountId: String(repeating: "3", count: 32), displayName: "Inès Moreau", roles: [.userManager, .auditor],
                state: .active, devices: [FfiOrgDevice(fingerprint: hex("e5d8"), name: "iPad d'Inès")], formerOwner: false),
            FfiOrgMember(
                accountId: String(repeating: "4", count: 32), displayName: "Sacha Roux", roles: [], state: .suspended,
                devices: [FfiOrgDevice(fingerprint: hex("17aa"), name: nil)], formerOwner: false),
            FfiOrgMember(
                accountId: String(repeating: "6", count: 32), displayName: "Jules Bernard", roles: [],
                state: .removed(at: 1_762_000_000, by: owner), devices: [], formerOwner: false),
        ]
        let mine = FfiOrgMember(
            accountId: me, displayName: DemoData.displayName, roles: joining ? [] : [.owner],
            state: joining ? .invited : .active,
            devices: joining ? [] : [FfiOrgDevice(fingerprint: hex("a8f0"), name: "Mac de Camille")], formerOwner: false)
        members.insert(mine, at: 0)
        if joining {
            members.insert(
                FfiOrgMember(
                    accountId: owner, displayName: "Alice Garnier", roles: [.owner], state: .active,
                    devices: [FfiOrgDevice(fingerprint: hex("0d6c"), name: "Mac d'Alice")], formerOwner: false),
                at: 1)
        }
        return FfiOrgState(
            orgId: String(repeating: "0a", count: 16), name: "Atelier Atlas", fingerprint: Data(repeating: 0xA5, count: 32),
            fingerprintWords: [
                ["acorn", "bubble", "cactus", "dolphin", "ember"],
                ["fossil", "garnet", "hammock", "igloo", "jigsaw"],
                ["kettle", "lilac", "mango", "nectar", "oyster"],
                ["pepper", "quartz", "ribbon", "saddle", "tundra"],
            ],
            dnsValue: "v=op1; org=FEXVKGT4ZRNQ2HBW7YDJ5MSC3LAPO6EI",
            source: joining ? .tofu(verified: false) : .dns, lineageGeneration: 1, rosterSeq: 6,
            owners: [owner], members: members)
    }
}

/// The demo's device keys: the fake backend never signs, so nothing reads them.
struct DemoOrgKeys: DeviceKeySource {
    func deviceKeys() throws -> DeviceKeyPair { DeviceKeyPair(classical: Data(count: 32), pq: DemoPqHalf()) }
}

private final class DemoPqHalf: FfiPqDeviceHalf, @unchecked Sendable {
    func mldsaPublic() throws -> Data { Data() }
    func mlkemPublic() throws -> Data { Data() }
    func mldsaSign(message: Data) throws -> Data { Data() }
    func mlkemDecapsulate(ciphertext: Data) throws -> Data { Data() }
}

extension AppModel {
    /// `-OnePassDemoOrg YES|join`: the Organisation page of the personal demo account shows the made-up
    /// organisation (`demoOrgSession`). `join` also marks the join request as posted with its code.
    func showDemoOrg(_ mode: String) {
        guard let accountID = session.environment.settings.accountID else { return }
        let joining = mode == "join"
        let settings = session.environment.settings
        settings.orgDomain = "atlas.exemple.fr"
        if joining {
            settings.orgJoinNonce = String(repeating: "0", count: 64)
            settings.orgJoinPosted = true
            settings.orgJoinCode = ["harbor", "velvet", "simmer", "outfit", "lagoon"]
        }
        let org = OrgSession(
            vault: session, backend: DemoOrgBackend(me: accountID, joining: joining), keys: DemoOrgKeys())
        demoOrgSession = org
        Task { await org.load() }
    }
}
#endif
