import CryptoKit
import Foundation

/// The watch's settings and last balances, one encrypted file per account next to its store
/// (`<store>.cryptowatch`): AES-256-GCM under a random key kept in the Keychain (this device only),
/// with the account id as associated data. A file that does not open (other key, tampered,
/// truncated) reads as a fresh state: it holds nothing that cannot be fetched again.
public struct CryptoWatchStore: Sendable {
    public let fileURL: URL
    private let keychain: any KeychainStore
    private let accountID: String

    static let keyPrefix = "cryptowatch.key."
    static let magic = Data("OPCW1".utf8)

    public init(fileURL: URL, keychain: any KeychainStore, accountID: String) {
        self.fileURL = fileURL
        self.keychain = keychain
        self.accountID = accountID
    }

    /// The store of a session's account.
    public init(environment: VaultEnvironment, accountID: String) {
        self.init(
            fileURL: environment.databaseURL.appendingPathExtension("cryptowatch"),
            keychain: environment.keychain, accountID: accountID)
    }

    private var keyName: String { Self.keyPrefix + accountID }
    private var aad: Data { Data("onepass.cryptowatch.v1:\(accountID)".utf8) }

    private func key(create: Bool) throws -> SymmetricKey? {
        if let data = try keychain.read(keyName), data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard create else { return nil }
        let key = SymmetricKey(size: .bits256)
        try keychain.write(keyName, key.withUnsafeBytes { Data($0) })
        return key
    }

    public func load() -> CryptoWatchState {
        guard let data = try? Data(contentsOf: fileURL), data.starts(with: Self.magic),
              let key = try? key(create: false),
              let box = try? AES.GCM.SealedBox(combined: data.dropFirst(Self.magic.count)),
              let plain = try? AES.GCM.open(box, using: key, authenticating: aad),
              let state = try? JSONDecoder().decode(CryptoWatchState.self, from: plain)
        else { return CryptoWatchState() }
        return state
    }

    public func save(_ state: CryptoWatchState) throws {
        let plain = try JSONEncoder().encode(state)
        guard let key = try key(create: true) else { return }
        let sealed = try AES.GCM.seal(plain, using: key, authenticating: aad)
        guard let combined = sealed.combined else { return }
        var out = Self.magic
        out.append(combined)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        #if os(iOS) || os(watchOS) || os(visionOS)
        try out.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try out.write(to: fileURL, options: .atomic)
        #endif
    }

    /// Forgets everything: the file and its key (turning the watch off, removing the account).
    public func erase() {
        try? FileManager.default.removeItem(at: fileURL)
        try? keychain.delete(keyName)
    }
}
