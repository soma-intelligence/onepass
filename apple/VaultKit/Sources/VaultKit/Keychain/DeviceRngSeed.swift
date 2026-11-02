import Foundation
import OnePassCore

/// This install's seed for the core's hedged random source (`docs/security.md`, "Randomness"):
/// 32 bytes made once by the core, kept in the keychain (`SystemKeychain`, so
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synchronizable, in the shared access group
/// so the AutoFill extension uses the same seed), and handed to the core at every launch.
///
/// Best effort by design: when the keychain cannot answer (locked device, missing entitlement),
/// nothing is created or replaced and the core keeps drawing from the OS generator alone, which is
/// what it does without a seed. A seed is only ever created when the keychain says none exists.
public enum DeviceRngSeed {
    static let key = "onepass.rng.device-seed"

    /// Reads the seed (creating it on first use) and installs it in the core. Returns whether a seed
    /// is now installed.
    @discardableResult
    public static func install(keychain: any KeychainStore) -> Bool {
        do {
            if let seed = try keychain.read(key) {
                try setDeviceRngSeed(seed: seed)
                return true
            }
            let seed = try newDeviceRngSeed()
            try keychain.write(key, seed)
            try setDeviceRngSeed(seed: seed)
            return true
        } catch {
            return false
        }
    }
}
