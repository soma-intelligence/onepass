import Foundation
import OnePassCore
import Testing

@testable import CompanionLink

private let seed = "JBSWY3DPEHPK3PXP"

/// Phone side of the tests: a real core account (test XCFramework, fast KDF) with items marked
/// for the watch. Sealing goes through `Session.companionPayload`, exactly like the app.
@MainActor
private final class PhoneCore {
    let dir: URL
    let session: Session
    let vaultID: String

    /// Account creation runs Argon2id (debug core, several seconds): off the main actor, so the
    /// tests of the suite create their accounts in parallel.
    static func make() async throws -> PhoneCore {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dbPath = dir.appendingPathComponent("vault.db").path
        let session = try await Task.detached {
            try createAccountWithKdf(
                dbPath: dbPath, password: "correct horse battery staple", kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1)
            ).session
        }.value
        return try PhoneCore(dir: dir, session: session)
    }

    private init(dir: URL, session: Session) throws {
        self.dir = dir
        self.session = session
        vaultID = try session.createVault(
            meta: FfiVaultMeta(name: "Personnel", icon: "person", color: "blue", travelSafe: false, mcpAccess: false)
        ).id
        try addWatchLogin(title: "Exemple Atlas")
    }

    func addWatchLogin(title: String) throws {
        var item = try session.newItem(vaultId: vaultID, itemType: .login, title: title)
        item.onWatch = true
        var otpSet = false
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices {
                let field = item.sections[s].fields[f]
                if field.kind == .otp {
                    item.sections[s].fields[f].value = .otp(value: seed)
                    otpSet = true
                } else if field.required && field.value == .empty {
                    item.sections[s].fields[f].value = switch field.kind {
                    case .password: .password(value: "motdepasse-fictif")
                    case .email: .email(value: "camille.durand@exemple.fr")
                    case .url: .url(value: "https://exemple.fr")
                    case .concealed: .concealed(value: "valeur-fictive")
                    default: .text(value: "Camille Durand")
                    }
                }
            }
        }
        #expect(otpSet)
        _ = try session.saveItem(item: item)
    }

    func seal(_ recipient: Data, _ generation: UInt64) throws -> Data {
        try session.companionPayload(
            recipientPublic: recipient, generation: generation, nowUnix: Int64(Date().timeIntervalSince1970),
            excludedVaultIds: [])
    }

    func cleanUp() {
        session.lock()
        try? FileManager.default.removeItem(at: dir)
    }
}

private struct SealRefused: Error {}

@MainActor
private final class Rig {
    let core: PhoneCore
    let phoneLink: InMemoryTransport
    let watchLink: InMemoryTransport
    let suite = "companion-tests-\(UUID().uuidString)"
    let defaults: UserDefaults
    let keys: InMemoryWatchKeyStore
    let payloadURL: URL
    var phone: PhoneCompanion!
    let watch: WatchVault
    var sealFails = false

    init(passcodeSet: Bool = true) async throws {
        core = try await PhoneCore.make()
        (phoneLink, watchLink) = InMemoryTransport.pair()
        defaults = UserDefaults(suiteName: suite)!
        keys = InMemoryWatchKeyStore(passcodeSet: passcodeSet)
        payloadURL = core.dir.appendingPathComponent("watch/payload.bin")
        watch = WatchVault(transport: watchLink, keys: keys, payloadURL: payloadURL)
        phone = makePhone(defaults: defaults)
    }

    func makePhone(defaults: UserDefaults) -> PhoneCompanion {
        PhoneCompanion(transport: phoneLink, defaults: defaults) { [unowned self] key, generation in
            if self.sealFails { throw SealRefused() }
            return try self.core.seal(key, generation)
        }
    }

    /// Starts both sides and waits for the phone's answer to the watch key.
    func startBoth() async {
        phone.start()
        watch.start()
        await phone.settle()
    }

    var payloads: [Data] {
        phoneLink.sent.compactMap { if case .payload(let d) = $0 { d } else { nil } }
    }

    var watchKeys: [Data] {
        watchLink.sent.compactMap { if case .watchKey(let k) = $0 { k } else { nil } }
    }

    func cleanUp() {
        defaults.removePersistentDomain(forName: suite)
        core.cleanUp()
    }
}

/// Generations come from the clock in milliseconds: wait so that the next one differs.
private func nextMillisecond() async throws {
    try await Task.sleep(for: .milliseconds(3))
}

@MainActor
struct CompanionLinkTests {
    @Test func watchSendsKeyOnStart() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        rig.watch.start()
        #expect(rig.watchKeys.count == 1)
        #expect(try rig.keys.loadPublicKey() == rig.watchKeys.first)
        #expect(try rig.keys.loadSecret() != nil)
        #expect(rig.watch.state == .waitingForPhone)

        // A restart resends the same key.
        rig.watch.start()
        #expect(rig.watchKeys.count == 2)
        #expect(rig.watchKeys[0] == rig.watchKeys[1])
    }

    @Test func phoneSendsAfterKeyArrives() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        #expect(rig.phone.watchPublicKey == rig.watchKeys.first)
        #expect(rig.payloads.count == 1)
        #expect(rig.phone.generation > 0)
        #expect(rig.phone.lastSent != nil)
        #expect(rig.watch.state == .ready)
        #expect(rig.watch.entries.count == 1)
        #expect(rig.watch.entries[0].title == "Exemple Atlas")
        let code = rig.watch.code(for: rig.watch.entries[0].itemId, at: Date())
        #expect(code?.code.count == 6)
        #expect(FileManager.default.fileExists(atPath: rig.payloadURL.path))
        #expect(try rig.keys.loadGeneration() == rig.phone.generation)
    }

    @Test func lockedPhoneSendsNothing() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        rig.sealFails = true
        await rig.startBoth()
        #expect(rig.phone.watchPublicKey != nil)
        #expect(rig.payloads.isEmpty)
        #expect(rig.phone.generation == 0)
        #expect(rig.phone.lastSent == nil)
        #expect(rig.watch.state == .waitingForPhone)
    }

    @Test func replayIsRejected() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let first = try #require(rig.payloads.first)

        try rig.core.addWatchLogin(title: "Exemple Boreal")
        await rig.phone.vaultChanged()
        #expect(rig.watch.entries.count == 2)
        let accepted = try rig.keys.loadGeneration()

        try rig.phoneLink.sendLatest(.payload(first))
        #expect(rig.watch.entries.count == 2)
        #expect(try rig.keys.loadGeneration() == accepted)
        #expect(rig.watchLink.sent.contains(.refreshRequest))
        await rig.phone.settle()
    }

    @Test func tamperedPayloadAsksForRefresh() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        var bad = try #require(rig.payloads.first)
        bad[bad.count - 1] ^= 0x01
        try rig.phoneLink.sendLatest(.payload(bad))
        #expect(rig.watch.entries.count == 1)
        #expect(rig.watchLink.sent.filter { $0 == .refreshRequest }.count == 1)

        // A second failure in a row does not ask again (no ping-pong with a phone stuck on a bad key).
        try rig.phoneLink.sendLatest(.payload(bad))
        #expect(rig.watchLink.sent.filter { $0 == .refreshRequest }.count == 1)

        // The phone answers the request with a fresh generation.
        let before = rig.payloads.count
        await rig.phone.settle()
        #expect(rig.payloads.count == before + 1)
        #expect(rig.watch.entries.count == 1)
    }

    @Test func generationSurvivesLostCounter() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let accepted = try rig.keys.loadGeneration()
        #expect(accepted > 0)

        // The phone loses its settings (reinstall): fresh defaults, counter back to zero.
        let freshSuite = "companion-tests-\(UUID().uuidString)"
        let fresh = UserDefaults(suiteName: freshSuite)!
        defer { fresh.removePersistentDomain(forName: freshSuite) }
        rig.phone = rig.makePhone(defaults: fresh)
        #expect(rig.phone.generation == 0)
        try rig.core.addWatchLogin(title: "Exemple Boreal")
        try await nextMillisecond()

        rig.phone.start()
        rig.watch.start()
        await rig.phone.settle()
        #expect(try rig.keys.loadGeneration() > accepted)
        #expect(rig.watch.entries.count == 2)
    }

    @Test func wipeClearsAndRekeys() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let oldKey = try #require(rig.watchKeys.first)
        #expect(rig.watch.entries.count == 1)

        rig.phone.wipeWatch()
        #expect(rig.phoneLink.sent.last == .wipe)
        #expect(!FileManager.default.fileExists(atPath: rig.payloadURL.path))
        #expect(rig.watch.entries.isEmpty)
        let newKey = try #require(rig.watchKeys.last)
        #expect(newKey != oldKey)
        #expect(try rig.keys.loadPublicKey() == newKey)
        #expect(try rig.keys.loadGeneration() == 0)
        // The phone forgot the old key and learned the new one from the restarted watch.
        #expect(rig.phone.watchPublicKey == newKey)
        // Sending is off: the unlocked phone does not refill the watch it just wiped.
        #expect(!rig.phone.isEnabled)
        #expect(rig.defaults.object(forKey: "companion.enabled") as? Bool == false)
        let sentBefore = rig.payloads.count
        await rig.phone.settle()
        await rig.phone.vaultChanged()
        #expect(rig.payloads.count == sentBefore)
        #expect(rig.watch.entries.isEmpty)

        // Turning the setting back on sends to the new key.
        rig.phone.isEnabled = true
        await rig.phone.vaultChanged()
        #expect(rig.payloads.count == sentBefore + 1)
        #expect(rig.watch.entries.count == 1)
    }

    @Test func failedKeyDeletionLeavesPendingWipe() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let oldKey = try #require(rig.watchKeys.first)
        let keysSent = rig.watchKeys.count
        #expect(rig.watch.entries.count == 1)

        rig.keys.deleteFails = true
        rig.phone.wipeWatch()
        #expect(rig.watch.entries.isEmpty)
        #expect(rig.watch.state == .closed)
        // The old key is still there but never resent, and the stored payload is not reopened.
        #expect(try rig.keys.loadPublicKey() == oldKey)
        #expect(rig.watchKeys.count == keysSent)
        rig.watch.activate()
        #expect(rig.watch.entries.isEmpty)
        rig.watch.start()
        #expect(rig.watch.entries.isEmpty)
        #expect(rig.watchKeys.count == keysSent)

        // The keychain works again: the next start finishes the wipe and rekeys.
        rig.keys.deleteFails = false
        rig.watch.start()
        #expect(!FileManager.default.fileExists(atPath: rig.payloadURL.path))
        let newKey = try #require(rig.watchKeys.last)
        #expect(newKey != oldKey)
        #expect(try rig.keys.loadPublicKey() == newKey)
        #expect(try rig.keys.loadGeneration() == 0)
        await rig.phone.settle()
        #expect(rig.phone.watchPublicKey == newKey)
        #expect(rig.watch.state == .waitingForPhone)
    }

    @Test func malformedWatchKeyIsIgnored() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let goodKey = try #require(rig.phone.watchPublicKey)
        #expect(goodKey.count == 1600)
        let sentBefore = rig.payloads.count

        rig.watchLink.onMessage = nil
        for bad in [Data(), Data(count: 1599), Data(count: 1601), Data(count: 32)] {
            rig.watchLink.sendQueued(.watchKey(bad))
            await rig.phone.settle()
        }
        #expect(rig.phone.watchPublicKey == goodKey)
        #expect(rig.defaults.data(forKey: "companion.watchKey") == goodKey)
        #expect(rig.payloads.count == sentBefore)
    }

    @Test func keyChangeTriggersSend() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        #expect(rig.payloads.count == 1)

        // Same key again (watch restart): nothing to send.
        rig.watch.start()
        await rig.phone.settle()
        #expect(rig.payloads.count == 1)

        // A new key (watch reset, the old app is gone): stored, then a payload sealed for it.
        rig.watchLink.onMessage = nil
        let other = try companionGenerateKey()
        rig.watchLink.sendQueued(.watchKey(other.public))
        await rig.phone.settle()
        #expect(rig.phone.watchPublicKey == other.public)
        #expect(rig.payloads.count == 2)
        let vault = try CompanionVault.open(secret: other.secret, sealed: rig.payloads[1])
        #expect(vault.entries().count == 1)
        #expect(vault.generation() == rig.phone.generation)
    }

    @Test func passcodeMissingBlocks() async throws {
        let rig = try await Rig(passcodeSet: false)
        defer { rig.cleanUp() }
        await rig.startBoth()
        #expect(rig.watch.state == .needsPasscode)
        #expect(rig.watchLink.sent.isEmpty)
        #expect(rig.phoneLink.sent.isEmpty)
        #expect(try rig.keys.loadSecret() == nil)
        rig.watch.activate()
        #expect(rig.watch.state == .needsPasscode)

        // The user adds a passcode and reopens the app: key created, sent, payload received.
        rig.keys.passcodeSet = true
        rig.watch.start()
        #expect(rig.watchKeys.count == 1)
        await rig.phone.settle()
        #expect(rig.watch.state == .ready)
        #expect(rig.watch.entries.count == 1)
    }

    @Test func deactivateDropsEntries() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let itemID = try #require(rig.watch.entries.first?.itemId)

        rig.watch.deactivate()
        #expect(rig.watch.state == .closed)
        #expect(rig.watch.entries.isEmpty)
        #expect(rig.watch.code(for: itemID, at: Date()) == nil)

        // A payload arriving in the background is stored but not opened.
        try rig.core.addWatchLogin(title: "Exemple Boreal")
        await rig.phone.vaultChanged()
        #expect(rig.watch.state == .closed)
        #expect(rig.watch.entries.isEmpty)

        rig.watch.activate()
        #expect(rig.watch.state == .ready)
        #expect(rig.watch.entries.count == 2)
        #expect(rig.watch.code(for: itemID, at: Date()) != nil)
    }

    @Test func disabledSendsNothing() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        #expect(rig.phone.isEnabled)
        rig.phone.isEnabled = false
        #expect(rig.defaults.object(forKey: "companion.enabled") as? Bool == false)
        await rig.startBoth()
        await rig.phone.vaultChanged()
        #expect(rig.payloads.isEmpty)
        #expect(rig.phone.generation == 0)
        // The key is still kept for when the user turns the setting back on.
        #expect(rig.phone.watchPublicKey != nil)
    }

    @Test func notReadyPhoneSendsNothing() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        rig.phoneLink.status = .appNotInstalled
        await rig.startBoth()
        #expect(rig.phone.status == .appNotInstalled)
        #expect(rig.payloads.isEmpty)
    }

    @Test func phoneStatePersists() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let restored = rig.makePhone(defaults: rig.defaults)
        #expect(restored.watchPublicKey == rig.phone.watchPublicKey)
        #expect(restored.generation == rig.phone.generation)
        #expect(restored.lastSent != nil)
    }

    @Test func wipeIsNotUndoneByStaleKey() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let oldKey = try #require(rig.watchKeys.first)
        let sentBefore = rig.payloads.count

        // The watch has not processed the wipe yet when its queued old key reaches the phone.
        rig.watchLink.onMessage = nil
        rig.phone.wipeWatch()
        #expect(rig.phoneLink.sent.filter { $0 == .wipe }.count == 2)
        #expect(rig.phone.lastError == nil)
        rig.watchLink.sendQueued(.watchKey(oldKey))
        await rig.phone.settle()
        #expect(rig.phone.watchPublicKey == nil)
        #expect(rig.payloads.count == sentBefore)

        // Still ignored after a relaunch of the phone app.
        rig.phone = rig.makePhone(defaults: rig.defaults)
        rig.phone.start()
        rig.watchLink.sendQueued(.watchKey(oldKey))
        await rig.phone.settle()
        #expect(rig.payloads.count == sentBefore)

        // The rekeyed watch's new key resumes sending once the setting is back on.
        #expect(!rig.phone.isEnabled)
        rig.phone.isEnabled = true
        let fresh = try companionGenerateKey()
        rig.watchLink.sendQueued(.watchKey(fresh.public))
        await rig.phone.settle()
        #expect(rig.phone.watchPublicKey == fresh.public)
        #expect(rig.payloads.count == sentBefore + 1)
    }

    @Test func wipeSendFailureIsPublished() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        rig.phoneLink.sendLatestError = SealRefused()
        rig.phone.wipeWatch()
        #expect(rig.phone.lastError == .wipeFailed)
        // The queued copy still went out.
        #expect(rig.phoneLink.sent.last == .wipe)

        rig.phoneLink.sendLatestError = nil
        rig.phone.isEnabled = true
        await rig.phone.vaultChanged()
        #expect(rig.phone.lastError == nil)
    }

    @Test func missedPayloadRequestsRefreshOnActivate() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        rig.watch.deactivate()

        // The watch is locked when the next payload arrives: dropped, no refresh yet.
        rig.keys.isLocked = true
        try rig.core.addWatchLogin(title: "Exemple Boreal")
        await rig.phone.vaultChanged()
        #expect(!rig.watchLink.sent.contains(.refreshRequest))
        rig.watch.activate()
        #expect(rig.watch.state == .closed)
        #expect(!rig.watchLink.sent.contains(.refreshRequest))

        // A relaunched watch app remembers the miss too.
        let relaunched = WatchVault(transport: rig.watchLink, keys: rig.keys, payloadURL: rig.payloadURL)
        rig.keys.isLocked = false
        relaunched.start()
        #expect(rig.watchLink.sent.filter { $0 == .refreshRequest }.count == 1)
        await rig.phone.settle()
        #expect(relaunched.entries.count == 2)

        // Accepted: the miss is cleared, the next activation asks for nothing.
        relaunched.deactivate()
        relaunched.activate()
        #expect(rig.watchLink.sent.filter { $0 == .refreshRequest }.count == 1)
    }

    @Test func unreadableGenerationRefusesPayload() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let floor = try rig.keys.loadGeneration()
        let first = try #require(rig.payloads.first)

        rig.keys.generationReadFails = true
        try rig.core.addWatchLogin(title: "Exemple Boreal")
        await rig.phone.vaultChanged()
        #expect(rig.watch.entries.count == 1)
        try rig.phoneLink.sendLatest(.payload(first))
        #expect(rig.watch.entries.count == 1)

        rig.keys.generationReadFails = false
        #expect(try rig.keys.loadGeneration() == floor)
        rig.watch.deactivate()
        rig.watch.activate()
        await rig.phone.settle()
        #expect(rig.watch.entries.count == 2)
    }

    @Test func generationSavedBeforeFile() async throws {
        let rig = try await Rig()
        defer { rig.cleanUp() }
        await rig.startBoth()
        let first = try #require(rig.payloads.first)

        // Make the file write fail: a directory now sits at the payload path.
        try FileManager.default.removeItem(at: rig.payloadURL)
        try FileManager.default.createDirectory(at: rig.payloadURL, withIntermediateDirectories: false)
        try rig.core.addWatchLogin(title: "Exemple Boreal")
        await rig.phone.vaultChanged()
        #expect(try rig.keys.loadGeneration() == rig.phone.generation)

        // The floor was raised before the write failed: the older payload is refused.
        try FileManager.default.removeItem(at: rig.payloadURL)
        rig.watch.deactivate()
        try rig.phoneLink.sendLatest(.payload(first))
        #expect(!FileManager.default.fileExists(atPath: rig.payloadURL.path))
        #expect(try rig.keys.loadGeneration() == rig.phone.generation)
        await rig.phone.settle()
    }

    @Test func messageDictionaryRoundTrip() {
        let messages: [CompanionMessage] = [
            .watchKey(Data([1, 2, 3])), .payload(Data([4, 5])), .wipe, .refreshRequest,
        ]
        for message in messages {
            #expect(CompanionMessage(dictionary: message.dictionary) == message)
        }
        #expect(CompanionMessage.refreshRequest.dictionary["kind"] as? String == "refresh")
        #expect(CompanionMessage.wipe.dictionary["nonce"] as? String != CompanionMessage.wipe.dictionary["nonce"] as? String)
        #expect(CompanionMessage(dictionary: ["kind": "launch"]) == nil)
        #expect(CompanionMessage(dictionary: [:]) == nil)
        #expect(CompanionMessage(dictionary: ["kind": "payload"]) == nil)
        #expect(CompanionMessage(dictionary: ["kind": "watchKey", "data": "texte"]) == nil)
    }
}
