import Foundation

/// One account of the device, as the apps show it (multi-account spec 4 and 7).
public struct AccountProfile: Identifiable, Equatable, Sendable {
    /// `primary`, or 32 hex characters.
    public let slot: String
    public let accountID: String?
    public let kind: FfiAccountKind
    /// Empty for the primary account until the user names it (the apps show the profile name).
    public let label: String
    public let color: FfiAccountColor
    public let workDomains: [String]

    public var id: String { slot }
    public var isPrimary: Bool { slot == AccountDirectoryStore.primarySlot }

    public var isManaged: Bool {
        if case .managed = kind { return true }
        return false
    }

    init(_ entry: FfiAccountEntry) {
        slot = entry.slot
        accountID = entry.accountId
        kind = entry.kind
        label = entry.label
        color = entry.color
        workDomains = entry.workDomains
    }

    /// The SF Symbol of the kind: a person, a briefcase, a building.
    public var symbol: String { Self.symbol(for: kind) }

    public static func symbol(for kind: FfiAccountKind) -> String {
        switch kind {
        case .personal: "person.fill"
        case .business: "briefcase.fill"
        case .managed: "building.2.fill"
        }
    }

    /// The color a new account of `kind` starts with.
    public static func defaultColor(for kind: FfiAccountKind) -> FfiAccountColor {
        switch kind {
        case .personal: .blue
        case .business: .orange
        case .managed: .indigo
        }
    }
}

/// Reads and writes the device's account directory (`accounts.json` next to the primary store) through
/// the core. Paths always derive from slots (spec M7).
public struct AccountDirectoryStore: Sendable {
    public static let primarySlot = "primary"

    /// The primary store's folder.
    public let folder: URL

    public init(folder: URL) {
        self.folder = folder
    }

    public init(container: SharedContainer) {
        folder = container.databaseFolder
    }

    public func load() throws -> FfiAccountDirectory {
        try accountDirectoryLoad(folder: folder.path)
    }

    public func add(kind: FfiAccountKind, label: String, color: FfiAccountColor) throws -> String {
        try accountDirectoryAdd(folder: folder.path, kind: kind, label: label, color: color)
    }

    @discardableResult
    public func bind(slot: String, accountID: String) throws -> FfiAccountDirectory {
        try accountDirectoryBind(folder: folder.path, slot: slot, accountId: accountID)
    }

    @discardableResult
    public func update(slot: String, label: String, color: FfiAccountColor, workDomains: [String]) throws
        -> FfiAccountDirectory
    {
        try accountDirectoryUpdate(
            folder: folder.path, slot: slot, label: label, color: color, workDomains: workDomains)
    }

    @discardableResult
    public func remove(slot: String) throws -> FfiAccountDirectory {
        try accountDirectoryRemove(folder: folder.path, slot: slot)
    }

    @discardableResult
    public func setActive(slot: String) throws -> FfiAccountDirectory {
        try accountDirectorySetActive(folder: folder.path, slot: slot)
    }

    @discardableResult
    public func reorder(slot: String, index: Int) throws -> FfiAccountDirectory {
        try accountDirectoryReorder(folder: folder.path, slot: slot, index: UInt32(max(0, index)))
    }

    @discardableResult
    public func setUnifiedSearch(_ enabled: Bool) throws -> FfiAccountDirectory {
        try accountDirectorySetUnifiedSearch(folder: folder.path, enabled: enabled)
    }

    /// The slot AutoFill uses for `host`: the account that claims it, else the primary one. A directory
    /// that does not load routes to the primary account.
    public func route(host: String) -> String {
        accountDirectoryRoute(folder: folder.path, host: host)
    }

    /// The store file of `slot`.
    public func databaseURL(slot: String) throws -> URL {
        URL(fileURLWithPath: try accountStorePath(folder: folder.path, slot: slot))
    }

    /// The folder only an added account's store lives in (never the primary store's folder).
    func slotFolder(slot: String) throws -> URL? {
        guard slot != Self.primarySlot else { return nil }
        return try databaseURL(slot: slot).deletingLastPathComponent()
    }

    /// The store of `slot` holds the account bound to the slot, or the slot is not bound yet (M4).
    public func checkBinding(slot: String) throws {
        try accountCheckBinding(folder: folder.path, slot: slot, dbPath: databaseURL(slot: slot).path)
    }
}
