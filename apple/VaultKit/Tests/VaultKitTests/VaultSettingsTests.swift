import Foundation
import Testing

@testable import VaultKit

@Suite("Settings and device mode")
struct VaultSettingsTests {
    func withSettings(_ body: (VaultSettings) throws -> Void) rethrows {
        let suite = "onepass.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        try body(VaultSettings(defaults: defaults))
    }

    @Test func settingsDefaults() {
        withSettings { s in
            #expect(s.deviceMode == .personal)
            #expect(s.autoLockDelay == .fifteenMinutes)
            #expect(s.hiddenVaultIDs.isEmpty)
            #expect(s.siteIconsEnabled)
            #expect(!s.biometricsWanted)
            #expect(!s.allowWatchUnlock)
            #expect(s.failedUnlocks == 0)
            #expect(s.lockoutUntil == nil)
            #expect(s.accountID == nil)
            #expect(s.displayName == "")
            #expect(s.effectiveAutoLockSeconds == 900)
        }
    }

    @Test func settingsPersist() {
        withSettings { s in
            s.hiddenVaultIDs = ["v1", "v2"]
            s.siteIconsEnabled = false
            s.failedUnlocks = 3
            let date = Date(timeIntervalSince1970: 5000)
            s.lockoutUntil = date
            s.accountID = "compte-1"
            s.displayName = "Camille Durand"
            s.autoLockDelay = .never
            #expect(s.hiddenVaultIDs == ["v1", "v2"])
            #expect(!s.siteIconsEnabled)
            #expect(s.failedUnlocks == 3)
            #expect(s.lockoutUntil == date)
            #expect(s.accountID == "compte-1")
            #expect(s.displayName == "Camille Durand")
            #expect(s.autoLockDelay == .never)
            s.lockoutUntil = nil
            #expect(s.lockoutUntil == nil)
        }
    }

    @Test func sharedModeForbidsBiometricsAndForcesFiveMinutes() {
        #expect(DeviceMode.personal.biometricsAllowed)
        #expect(DeviceMode.personal.forcedAutoLock == nil)
        #expect(!DeviceMode.shared.biometricsAllowed)
        #expect(DeviceMode.shared.forcedAutoLock == 300)
        withSettings { s in
            s.deviceMode = .shared
            s.autoLockDelay = .never
            #expect(s.effectiveAutoLockSeconds == 300)
            s.autoLockDelay = .oneMinute
            #expect(s.effectiveAutoLockSeconds == 60)
            s.autoLockDelay = .oneHour
            #expect(s.effectiveAutoLockSeconds == 300)
        }
    }

    @Test func failedUnlockCounterIsAtomic() async {
        let suite = "onepass.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let s = VaultSettings(defaults: defaults)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<200 { group.addTask { s.recordFailedUnlock() } }
        }
        #expect(s.failedUnlocks == 200)
        s.resetFailedUnlocks()
        #expect(s.failedUnlocks == 0)
    }
}
