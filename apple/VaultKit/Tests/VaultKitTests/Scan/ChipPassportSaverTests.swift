import Foundation
import OnePassCore
import Testing

@testable import VaultKit

/// A vault session where chosen calls fail once, and every call is counted.
@MainActor
final class FlakyChipStore: ChipItemStore {
    let session: VaultSession
    /// 1-based index of the `save` call that fails (once).
    var failSave: Int?
    var failRemove = false
    private(set) var saves = 0
    private(set) var adds = 0
    private(set) var removes = 0

    struct Injected: Error {}

    init(_ session: VaultSession) {
        self.session = session
    }

    func save(_ item: FfiItem) async throws -> FfiItem {
        saves += 1
        if saves == failSave {
            failSave = nil
            throw Injected()
        }
        return try await session.save(item)
    }

    func addAttachment(itemID: String, vaultID: String, name: String, mime: String, data: Data) async throws
        -> FfiItem
    {
        adds += 1
        return try await session.addAttachment(itemID: itemID, vaultID: vaultID, name: name, mime: mime, data: data)
    }

    func removeAttachment(itemID: String, vaultID: String, attachmentID: String) async throws -> FfiItem {
        removes += 1
        if failRemove {
            failRemove = false
            throw Injected()
        }
        return try await session.removeAttachment(itemID: itemID, vaultID: vaultID, attachmentID: attachmentID)
    }

    func storedItem(vaultID: String, itemID: String) async throws -> FfiItem {
        try await session.storedItem(vaultID: vaultID, itemID: itemID)
    }

    func mergeChip(item: FfiItem, read chip: FfiChipRead) async throws -> FfiChipMerge {
        try await session.mergeChip(item: item, read: chip)
    }
}

@MainActor
@Suite(.serialized) struct ChipPassportSaverTests {
    static let specimen = [
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
    ]
    static let jpegA = Data([0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 0xFF, 0xD9])
    static let jpegB = Data([0xFF, 0xD8, 0xFF, 0xE0, 4, 5, 6, 0xFF, 0xD9])

    private func read() throws -> FfiChipRead {
        FfiChipRead(mrz: try mrzParse(lines: Self.specimen), portrait: nil, portraitFormat: nil, status: .verified)
    }

    private func setUp() async throws -> (SessionHarness, VaultSession) {
        let h = try SessionHarness()
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return (h, session)
    }

    private func value(_ id: String, in item: FfiItem) -> FfiFieldValue? {
        item.sections.lazy.flatMap(\.fields).first { $0.id == id }?.value
    }

    private func portraits(_ item: FfiItem) -> [FfiAttachment] {
        item.attachments.filter { $0.name == ChipPassportSaver.portraitName }
    }

    @Test func savesThenLinksThePortrait() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: try read())
        let saved = try await ChipPassportSaver(store: session).save(item, portrait: Self.jpegA)
        #expect(portraits(saved).count == 1)
        #expect(ChipPassportSaver.portraitID(of: saved) == portraits(saved).first?.id)
        let bytes = try await session.attachmentData(
            itemID: saved.id, vaultID: saved.vaultId, attachmentID: try #require(portraits(saved).first).id)
        #expect(bytes == Self.jpegA)
    }

    /// The link step fails: the new file is removed, then "Enregistrer" again resumes from the
    /// stored item (no second item save, no second orphan).
    @Test func failedLinkRemovesTheFileAndRetryResumes() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: try read())
        let store = FlakyChipStore(session)
        store.failSave = 2
        let saver = ChipPassportSaver(store: store)
        await #expect(throws: FlakyChipStore.Injected.self) {
            _ = try await saver.save(item, portrait: Self.jpegA)
        }
        let afterFailure = try await session.storedItem(vaultID: item.vaultId, itemID: item.id)
        #expect(afterFailure.attachments.isEmpty)
        // Stored: the flow locks the reveal's choices from here on.
        #expect(saver.stored != nil)
        #expect(store.adds == 1 && store.removes == 1)

        let saved = try await saver.save(item, portrait: Self.jpegA)
        #expect(portraits(saved).count == 1)
        #expect(ChipPassportSaver.portraitID(of: saved) == portraits(saved).first?.id)
        // Item saved once, link failed once, link saved once.
        #expect(store.saves == 3)
    }

    /// A later read: the new portrait replaces the old one, exactly one file left.
    @Test func rescanReplacesThePortrait() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: Self.jpegA)
        let oldID = try #require(ChipPassportSaver.portraitID(of: first))

        let merged = try await session.mergeChip(item: first, read: chip).item
        let second = try await ChipPassportSaver(store: session).save(merged, rescan: chip, portrait: Self.jpegB)
        #expect(portraits(second).count == 1)
        let newID = try #require(ChipPassportSaver.portraitID(of: second))
        #expect(newID != oldID)
        #expect(!second.attachments.contains { $0.id == oldID })
    }

    /// The old portrait's removal fails: a retry only removes it.
    @Test func failedOldPortraitRemovalIsRetried() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: Self.jpegA)
        let merged = try await session.mergeChip(item: first, read: chip).item
        let store = FlakyChipStore(session)
        store.failRemove = true
        let saver = ChipPassportSaver(store: store)
        await #expect(throws: FlakyChipStore.Injected.self) {
            _ = try await saver.save(merged, rescan: chip, portrait: Self.jpegB)
        }
        let saved = try await saver.save(merged, rescan: chip, portrait: Self.jpegB)
        #expect(portraits(saved).count == 1)
        #expect(store.adds == 1 && store.saves == 2)
    }

    /// A field edited (synced) after the reveal was computed is not overwritten at save time.
    @Test func rescanKeepsEditsMadeSinceTheReveal() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: nil)
        let reveal = try await session.mergeChip(item: first, read: chip).item

        var edited = try await session.storedItem(vaultID: first.vaultId, itemID: first.id)
        edited.notes = "Renouvelé en 2026"
        ChipPassportSaver.setField("first_names", to: .text(value: "Anna"), in: &edited)
        _ = try await session.save(edited)

        let saved = try await ChipPassportSaver(store: session).save(reveal, rescan: chip, portrait: nil)
        #expect(saved.notes == "Renouvelé en 2026")
        #expect(value("first_names", in: saved) == .text(value: "Anna"))
    }

    /// A conflict settled for the chip takes the chip's value.
    @Test func chipValuesWinWhenPicked() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        var item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        ChipPassportSaver.setField("first_names", to: .text(value: "Anna"), in: &item)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: nil)
        let reveal = try await session.mergeChip(item: first, read: chip).item
        let saved = try await ChipPassportSaver(store: session).save(
            reveal, rescan: chip, chipValues: ["first_names": .text(value: "Anna Maria")], portrait: nil)
        #expect(value("first_names", in: saved) == .text(value: "Anna Maria"))
    }

    /// The link fails and so does removing the new file: the orphan is removed on the retry, and
    /// the portrait linked is the new file, not the orphan.
    @Test func failedCleanupOrphanIsRemovedOnRetry() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: try read())
        let store = FlakyChipStore(session)
        store.failSave = 2
        store.failRemove = true
        let saver = ChipPassportSaver(store: store)
        await #expect(throws: FlakyChipStore.Injected.self) {
            _ = try await saver.save(item, portrait: Self.jpegA)
        }
        let afterFailure = try await session.storedItem(vaultID: item.vaultId, itemID: item.id)
        let orphan = try #require(portraits(afterFailure).first)
        #expect(portraits(afterFailure).count == 1)

        let saved = try await saver.save(item, portrait: Self.jpegB)
        #expect(portraits(saved).count == 1)
        #expect(!saved.attachments.contains { $0.id == orphan.id })
        let linked = try #require(ChipPassportSaver.portraitID(of: saved))
        #expect(linked == portraits(saved).first?.id)
        let bytes = try await session.attachmentData(itemID: saved.id, vaultID: saved.vaultId, attachmentID: linked)
        #expect(bytes == Self.jpegB)
    }

    /// A chip value picked in the reveal for a field a synced edit has since made equal to the
    /// chip's: no conflict at save time, so the pick is not applied.
    @Test func chipValueSkippedWhenNoLongerInConflict() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        var item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        let chipNames = try #require(value("first_names", in: item))
        ChipPassportSaver.setField("first_names", to: .text(value: "Anna"), in: &item)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: nil)
        let reveal = try await session.mergeChip(item: first, read: chip)
        #expect(reveal.conflicts.contains { $0.fieldId == "first_names" })

        var edited = try await session.storedItem(vaultID: first.vaultId, itemID: first.id)
        ChipPassportSaver.setField("first_names", to: chipNames, in: &edited)
        _ = try await session.save(edited)

        let saved = try await ChipPassportSaver(store: session).save(
            reveal.item, rescan: chip, chipValues: ["first_names": .text(value: "Picked in the reveal")],
            portrait: nil)
        #expect(value("first_names", in: saved) == chipNames)
    }

    /// Once stored, a retry keeps the conflicts as saved (the flow locks the pickers).
    @Test func storedChoicesAreKeptOnRetry() async throws {
        let (h, session) = try await setUp()
        defer { h.cleanUp() }
        let chip = try read()
        var item = try await session.itemFromChip(vaultID: session.allVaults[0].id, read: chip)
        ChipPassportSaver.setField("first_names", to: .text(value: "Anna"), in: &item)
        let first = try await ChipPassportSaver(store: session).save(item, portrait: nil)
        let reveal = try await session.mergeChip(item: first, read: chip).item
        let store = FlakyChipStore(session)
        store.failSave = 2
        let saver = ChipPassportSaver(store: store)
        let picked: [String: FfiFieldValue] = ["first_names": .text(value: "Anna Maria")]
        await #expect(throws: FlakyChipStore.Injected.self) {
            _ = try await saver.save(reveal, rescan: chip, chipValues: picked, portrait: Self.jpegA)
        }
        let saved = try await saver.save(reveal, rescan: chip, chipValues: [:], portrait: Self.jpegA)
        #expect(value("first_names", in: saved) == .text(value: "Anna Maria"))
        #expect(portraits(saved).count == 1)
    }
}
