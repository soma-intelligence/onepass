import Foundation
import OnePassCore

/// Travel Mode (milestone 7, apps side): the vaults not marked safe for travel leave this device and
/// come back verified. The core never queues a deletion for iCloud: the server keeps every vault.
///
/// Entering needs every write of the leaving vaults pushed first (the app syncs, then calls
/// `enterTravel`). Leaving is two steps around a fetch from scratch: `beginTravelExit` lets the sync
/// bring the vaults back, `finishTravelExit` verifies them against the manifests this device saw last.
extension VaultSession {
    public func travelStatus() async throws -> FfiTravelStatus {
        try await read { try $0.travelStatus() }
    }

    /// Every vault and whether it leaves, for the confirmation sheet.
    public func travelPlan() async throws -> [FfiTravelPlanEntry] {
        try await read { try $0.travelPlan() }
    }

    @discardableResult
    public func enterTravel() async throws -> FfiTravelStatus {
        try await write { try $0.enterTravel() }
    }

    @discardableResult
    public func beginTravelExit() async throws -> FfiTravelStatus {
        try await read { try $0.beginTravelExit() }
    }

    /// A refused copy (an older state served again, a missing vault) is not a failure of the whole
    /// store: the core took it off the device again and the Travel Mode stays on. The error is thrown
    /// without the "Données refusées" screen, and the lists reload either way.
    @discardableResult
    public func finishTravelExit() async throws -> FfiTravelStatus {
        guard let session = coreSession else { throw VaultError.passwordRequired }
        noteActivity()
        do {
            let status = try await background { try session.finishTravelExit() }
            await refresh()
            return status
        } catch {
            await refresh()
            throw VaultError(error)
        }
    }
}
