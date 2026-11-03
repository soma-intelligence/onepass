import Foundation
import OnePassCore
import SafariRelay
import SafariServices
import VaultKit

/// iPhone and iPad (spec 2026-11-03-ios-safari-autofill): receives each
/// `browser.runtime.sendNativeMessage` of the OnePass Safari extension, the same messages as on the
/// Mac (`extension/src/background/safari.ts`). iOS has no app listening on a socket, so this process
/// opens the vault itself on the shared store (App Group, shared keychain group) and serves the
/// bridge in process (`BridgeServer.connectInProcess`, ruling I1): the same frames, pairing and
/// session as the Mac relay. The unlock sheet's `vault_state`, `unlock_biometric` and
/// `unlock_password` reach `ExtensionVault` (ruling I4), never the bridge.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// One vault and one hub for the life of the extension process: the unlocked session and the
    /// bridge connections survive between requests, and die with the process (ruling I3).
    private static let vault = ExtensionVault()
    private static let hub = RelayHub(
        launcher: InProcessHostLauncher(connect: { try vault.connect() }), openApp: nil, vault: vault)
    private static let queue = DispatchQueue(
        label: "me.somalabs.onepass.safari.relay", qos: .userInitiated, attributes: .concurrent)

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey]
        let request: Result<RelayRequest, RelayError>
        do {
            request = .success(try RelayRequest.parse(message))
        } catch {
            request = .failure(error)
        }
        let reply = Reply(context: context)
        // A poll blocks until the bridge speaks, an unlock until Face ID answers: never here.
        Self.queue.async {
            let response: RelayResponse
            switch request {
            case .success(let r): response = Self.hub.handle(r)
            case .failure(let e): response = .failure(e)
            }
            reply.send(response)
        }
    }
}

/// `SafariExtensionVault` (main actor) behind the relay's blocking `VaultGate`, called from the relay
/// queue. Created lazily on the main actor the first time a request needs it.
final class ExtensionVault: VaultGate, @unchecked Sendable {
    private let lock = NSLock()
    private var made: SafariExtensionVault?

    private func vault() -> SafariExtensionVault {
        lock.lock()
        defer { lock.unlock() }
        if let made { return made }
        let v: SafariExtensionVault =
            Thread.isMainThread
            ? MainActor.assumeIsolated { SafariExtensionVault(environment: .live()) }
            : DispatchQueue.main.sync { MainActor.assumeIsolated { SafariExtensionVault(environment: .live()) } }
        made = v
        return v
    }

    func connect() throws -> Int32 {
        try vault().connect()
    }

    func state() -> VaultReply {
        run { $0.state() }
    }

    func unlockBiometric() -> VaultReply {
        run { await $0.unlockWithBiometrics() }
    }

    func unlockPassword(_ password: Data) -> VaultReply {
        var copy = password
        // Takes the bytes and zeroes `copy`.
        let secret = SecretBytes(taking: &copy)
        return run { v in
            let s = await v.unlock(password: secret)
            secret.wipe()
            return s
        }
    }

    /// Hops to the main actor and blocks this relay thread until the answer.
    private func run(_ work: @escaping @MainActor @Sendable (SafariExtensionVault) async -> SafariExtensionVault.State)
        -> VaultReply
    {
        let v = vault()
        let done = DispatchSemaphore(value: 0)
        let box = Box()
        Task { @MainActor in
            box.value = await work(v)
            done.signal()
        }
        // Face ID never holds a relay thread forever.
        guard done.wait(timeout: .now() + .seconds(120)) == .success, let s = box.value else {
            return VaultReply(locked: true, failure: .failed)
        }
        return VaultReply(
            locked: s.locked, account: s.account, biometry: s.biometry,
            failure: s.failure.flatMap { VaultReply.Failure(rawValue: $0.rawValue) }, message: s.message)
    }

    private final class Box: @unchecked Sendable {
        var value: SafariExtensionVault.State?
    }
}

/// The request's context, completed once from the relay queue.
private final class Reply: @unchecked Sendable {
    private let context: NSExtensionContext

    init(context: NSExtensionContext) {
        self.context = context
    }

    func send(_ response: RelayResponse) {
        let item = NSExtensionItem()
        item.userInfo = [SFExtensionMessageKey: response.dictionary]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }
}
