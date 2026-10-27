import Foundation
import OnePassCore

extension VaultSession {
    /// The watch payload sealed to the watch public key. Hidden vaults are excluded.
    public func companionPayload(recipientPublicKey: Data, generation: UInt64, now: Date = .now) async throws -> Data {
        let excluded = Array(hiddenVaultIDs)
        let unix = Int64(now.timeIntervalSince1970)
        let sealed = try await read { session in
            try session.companionPayload(
                recipientPublic: recipientPublicKey, generation: generation,
                nowUnix: unix, excludedVaultIds: excluded)
        }
        return sealed
    }

    /// Favorites and their TOTP codes over `window` seconds. Hidden vaults are excluded.
    public func glanceSnapshot(window: TimeInterval, now: Date = .now) async throws -> FfiGlanceSnapshot {
        let excluded = Array(hiddenVaultIDs)
        let unix = Int64(now.timeIntervalSince1970)
        let secs = UInt64(max(0, window))
        return try await read { session in
            try session.glanceSnapshot(nowUnix: unix, windowSecs: secs, excludedVaultIds: excluded)
        }
    }
}
