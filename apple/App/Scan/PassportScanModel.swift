import Foundation
import OSLog
import VaultKit

/// What the scan flow does with the read: a new passport in a vault, or a later read of a passport
/// the vault already holds ("Scanner la puce" in its detail, spec 6.1).
enum ScanTarget: Equatable {
    case new(vaultID: String)
    case merge(FfiItem)
}

/// One chip read through one NFC session. The app's is Core NFC (`NFCChipLink`); Debug builds
/// can swap in a fake chip for the UI tests (`-OnePassFakeChip YES`).
@MainActor
protocol PassportChipLink: AnyObject {
    /// Reads the chip of the document these MRZ lines belong to. `progress` gets 0 to 1, from any
    /// thread.
    func read(mrz: [String], progress: @escaping @Sendable (Double) -> Void) async throws(PassportReadError)
        -> FfiChipRead
    /// Closes the system sheet: as a success (`errorMessage` nil) or with the message of the error.
    /// Called once on every way out of a read, cancel included.
    func close(errorMessage: String?)
}

/// The passport scan flow (spec 6.2): camera, "Pose ton téléphone", NFC read, reveal, save. Holds
/// the MRZ and the read only while the flow is on screen; nothing is logged but steps.
@MainActor
@Observable
final class PassportScanModel {
    enum Phase: Equatable {
        /// The camera looks for the two MRZ lines (or the user types them).
        case camera
        /// MRZ found: put the phone on the document, then read.
        case place
        /// Reading the chip, 0 to 1.
        case reading(Double)
        /// The chip was read: the item to save (new or merged) and the portrait as JPEG.
        case reveal(FfiItem, Data?)
        case failed(PassportReadError)
    }

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "scan")

    private(set) var phase: Phase = .camera
    /// The two lines found by the camera or typed.
    private(set) var mrz: [String]?
    /// A later read: the values the user typed that differ from the chip. Kept unless the user
    /// picks the chip's value (`takeScanned`).
    private(set) var conflicts: [FfiFieldConflict] = []
    /// Conflicts (field ids) for which the user picked the chip's value.
    var takeScanned: Set<String> = []

    let target: ScanTarget
    private let session: VaultSession
    private let makeLink: @MainActor () throws(PassportReadError) -> any PassportChipLink
    /// The chip's value of each conflicting field, as the core formats it (readable case, dates,
    /// concealed number): taken when the user picks the chip's side of a conflict.
    private var scannedValues: [String: FfiFieldValue] = [:]

    init(
        target: ScanTarget, session: VaultSession,
        makeLink: @escaping @MainActor () throws(PassportReadError) -> any PassportChipLink
    ) {
        self.target = target
        self.session = session
        self.makeLink = makeLink
    }

    /// The camera (or the typed lines) gave a MRZ that passed its check digits.
    func mrzFound(_ lines: [String]) {
        mrz = lines
        phase = .place
        Self.log.info("scan: MRZ found")
    }

    /// Back to the camera ("Rescanner la MRZ").
    func rescan() {
        mrz = nil
        scannedValues = [:]
        conflicts = []
        takeScanned = []
        phase = .camera
    }

    /// Back to "Pose ton téléphone" after a failure, MRZ kept ("Réessayer").
    func retry() {
        phase = mrz == nil ? .camera : .place
    }

    /// "Lecture de la puce, N %": the text of the system NFC sheet.
    nonisolated static func alertMessage(progress: Double) -> String {
        let percent = Int((min(max(progress, 0), 1) * 100).rounded())
        return String(localized: "scan.nfc.progress \(percent)")
    }

    /// Reads the chip through a new NFC session, then builds the item. The session is closed on
    /// every way out: success, failure, and the task being cancelled (the flow left the screen).
    func readChip() async {
        guard let mrz else { return }
        if case .reading = phase { return }
        phase = .reading(0)
        let link: any PassportChipLink
        do {
            link = try makeLink()
        } catch {
            phase = .failed(error)
            return
        }
        let read: FfiChipRead
        do {
            read = try await link.read(mrz: mrz) { [weak self] value in
                Task { @MainActor in
                    guard let self, case .reading = self.phase else { return }
                    self.phase = .reading(value)
                }
            }
        } catch {
            link.close(errorMessage: error == .cancelled ? nil : Self.message(for: error))
            if Task.isCancelled { return }
            // Closing the sheet is not an error: the user is back on "Pose ton téléphone".
            phase = error == .cancelled ? .place : .failed(error)
            return
        }
        link.close(errorMessage: nil)
        if Task.isCancelled { return }
        await present(read)
    }

    /// The item for the reveal: a new passport, or the stored one with the read merged in.
    private func present(_ read: FfiChipRead) async {
        var portrait: Data?
        if let bytes = read.portrait, let format = read.portraitFormat {
            portrait = try? PortraitConverter.jpeg(from: bytes, format: format)
        }
        do {
            switch target {
            case .new(let vaultID):
                let item = try await session.itemFromChip(vaultID: vaultID, read: read)
                conflicts = []
                phase = .reveal(item, portrait)
            case .merge(let stored):
                let merge = try await session.mergeChip(item: stored, read: read)
                if !merge.conflicts.isEmpty {
                    // The same read as a new item gives the chip's side of each conflict.
                    let fresh = try await session.itemFromChip(vaultID: stored.vaultId, read: read)
                    let ids = Set(merge.conflicts.map(\.fieldId))
                    scannedValues = Dictionary(
                        fresh.sections.flatMap(\.fields).filter { ids.contains($0.id) }.map { ($0.id, $0.value) },
                        uniquingKeysWith: { first, _ in first })
                }
                conflicts = merge.conflicts
                takeScanned = []
                phase = .reveal(merge.item, portrait)
            }
            Self.log.info("scan: chip read, \(self.conflicts.count) conflicts")
        } catch {
            Self.log.error("scan: the read did not become an item")
            phase = .failed(.unsupported)
        }
    }

    /// The reveal's item with the conflicts the user settled: the stored value stays unless the
    /// chip's was picked.
    func resolvedItem() -> FfiItem? {
        guard case .reveal(var item, _) = phase else { return nil }
        for conflict in conflicts where takeScanned.contains(conflict.fieldId) {
            if let value = scannedValues[conflict.fieldId] { Self.setField(conflict.fieldId, to: value, in: &item) }
        }
        return item
    }

    /// Saves: the item first, then the portrait as an encrypted attachment linked from the
    /// `portrait` field (a later read replaces the previous portrait). Returns the stored item.
    func save(vaultID: String) async throws -> FfiItem {
        guard var item = resolvedItem() else { throw VaultError.other("") }
        guard case .reveal(_, let portrait) = phase else { throw VaultError.other("") }
        if item.vaultId != vaultID, case .new = target {
            item.vaultId = vaultID
        }
        let previousPortrait = PassportBooklet.portraitAttachment(of: item)
        var stored = try await session.save(item)
        if let portrait {
            let withFile = try await session.addAttachment(
                itemID: stored.id, vaultID: stored.vaultId, name: "portrait.jpg", mime: "image/jpeg",
                data: portrait)
            let known = Set(stored.attachments.map(\.id))
            if let added = withFile.attachments.first(where: { !known.contains($0.id) }) {
                var linked = withFile
                Self.setField("portrait", to: .file(value: added), in: &linked)
                stored = try await session.save(linked)
                if let previousPortrait, previousPortrait.id != added.id,
                    stored.attachments.contains(where: { $0.id == previousPortrait.id })
                {
                    stored = try await session.removeAttachment(
                        itemID: stored.id, vaultID: stored.vaultId, attachmentID: previousPortrait.id)
                }
            } else {
                stored = withFile
            }
        }
        Self.log.info("scan: passport saved")
        return stored
    }

    static func setField(_ id: String, to value: FfiFieldValue, in item: inout FfiItem) {
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices where item.sections[s].fields[f].id == id {
                item.sections[s].fields[f].value = value
                return
            }
        }
    }

    /// No chip, or no NFC: a new passport from the MRZ alone, for the editor (spec 6.2, "Garder
    /// les données de la MRZ"). The core fills it as from a chip; the chip status and date are
    /// cleared since nothing was read.
    func mrzOnlyItem() async -> FfiItem? {
        guard case .new(let vaultID) = target, let mrz, let parsed = try? mrzParse(lines: mrz) else { return nil }
        let read = FfiChipRead(mrz: parsed, portrait: nil, portraitFormat: nil, status: .unverifiable)
        guard var item = try? await session.itemFromChip(vaultID: vaultID, read: read) else { return nil }
        Self.setField("chip_status", to: .empty, in: &item)
        Self.setField("chip_read_on", to: .empty, in: &item)
        return item
    }

    /// The message of a failure, as in the spec 6.2 table.
    nonisolated static func message(for error: PassportReadError) -> String {
        switch error {
        case .accessDenied: String(localized: "scan.error.accessDenied")
        case .lostContact: String(localized: "scan.error.lostContact")
        case .noChip: String(localized: "scan.error.noChip")
        case .nfcUnavailable: String(localized: "scan.error.nfcUnavailable")
        case .unsupported: String(localized: "scan.error.unsupported")
        case .cancelled: String(localized: "scan.error.cancelled")
        }
    }
}

/// The scan flow on screen (`AppModel.scanRequest`).
struct ScanRequest: Identifiable, Equatable {
    let id = UUID()
    let target: ScanTarget
}

#if os(iOS)
import UIKit

/// The iPhone's chip link: a Core NFC session (`NFCTransport`) and a reader that checks the chip
/// against the bundled CSCA master list. The system sheet shows "Lecture de la puce, N %".
final class NFCChipLink: PassportChipLink {
    private let transport: NFCTransport
    private let reader: PassportReader

    init() throws(PassportReadError) {
        let transport = try NFCTransport(alertMessage: String(localized: "scan.nfc.hold"))
        guard let reader = CSCAMasterList.reader(transport: transport) else {
            transport.invalidate(errorMessage: PassportScanModel.message(for: .unsupported))
            throw .unsupported
        }
        self.transport = transport
        self.reader = reader
    }

    func read(mrz: [String], progress: @escaping @Sendable (Double) -> Void) async throws(PassportReadError)
        -> FfiChipRead
    {
        let transport = transport
        return try await reader.read(mrz: mrz) { value in
            transport.setAlertMessage(PassportScanModel.alertMessage(progress: value))
            progress(value)
        }
    }

    func close(errorMessage: String?) {
        transport.invalidate(errorMessage: errorMessage)
    }
}

/// How the flow reads chips on this device.
enum ChipLinks {
    /// The camera of the flow is a fixed MRZ, and the chip a fake (UI tests, Debug only).
    @MainActor static var isFake: Bool {
        #if DEBUG
        FakeChipLink.isOn
        #else
        false
        #endif
    }

    @MainActor static func make() throws(PassportReadError) -> any PassportChipLink {
        #if DEBUG
        if FakeChipLink.isOn { return FakeChipLink() }
        #endif
        return try NFCChipLink()
    }
}

#if DEBUG
/// UI tests (`-OnePassFakeChip YES`, Debug builds only): the camera "reads" the ICAO specimen MRZ
/// of the core's replay fixture (`-OnePassFakeChipMRZ other`: another valid MRZ), and the chip
/// answers that specimen only. A read with any other MRZ goes through the real reader and a real
/// core session against a chip that refuses the keys, so the access denied path is the app's own.
/// The shipped bindings have no replayable session (`scan-test-rng` is test-only), so the
/// specimen's answer is the read itself: the specimen MRZ, a drawn portrait, a verified status.
final class FakeChipLink: PassportChipLink {
    nonisolated static var isOn: Bool { UserDefaults.standard.bool(forKey: "OnePassFakeChip") }

    /// core/onepass-core/tests/fixtures/icao/session_pace.json.
    nonisolated static let specimen = [
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
    ]
    /// Valid check digits, another document number: not the fake chip's.
    nonisolated static let other = [
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "X123456785UTO7408122F1204159ZE184226B<<<<<12",
    ]

    /// What the fake camera reads.
    nonisolated static var cameraMRZ: [String] {
        UserDefaults.standard.string(forKey: "OnePassFakeChipMRZ") == "other" ? other : specimen
    }

    func read(mrz: [String], progress: @escaping @Sendable (Double) -> Void) async throws(PassportReadError)
        -> FfiChipRead
    {
        guard mrz == Self.specimen else {
            guard let reader = CSCAMasterList.reader(transport: RefusingChip()) else { throw .unsupported }
            return try await reader.read(mrz: mrz, progress: progress)
        }
        for step in 1...5 {
            try? await Task.sleep(for: .milliseconds(120))
            if Task.isCancelled { throw .cancelled }
            progress(Double(step) / 5)
        }
        guard let parsed = try? mrzParse(lines: mrz) else { throw .unsupported }
        return FfiChipRead(mrz: parsed, portrait: Self.portrait(), portraitFormat: .jpeg, status: .verified)
    }

    func close(errorMessage: String?) {}

    /// A plain drawn head and shoulders, 3:4, as JPEG: no real face anywhere.
    private static func portrait() -> Data? {
        let size = CGSize(width: 120, height: 160)
        let image = UIGraphicsImageRenderer(size: size).image { context in
            UIColor(white: 0.86, alpha: 1).setFill()
            context.fill(CGRect(origin: .zero, size: size))
            UIColor(white: 0.55, alpha: 1).setFill()
            context.cgContext.fillEllipse(in: CGRect(x: 36, y: 30, width: 48, height: 58))
            context.cgContext.fillEllipse(in: CGRect(x: 14, y: 100, width: 92, height: 100))
        }
        return image.jpegData(compressionQuality: 0.8)
    }
}

/// A chip without EF.CardAccess that refuses BAC (6300): keys from another document's MRZ.
private struct RefusingChip: APDUTransport {
    func send(_ apdu: Data) async throws -> Data {
        let b = [UInt8](apdu)
        guard b.count >= 3 else { return Data([0x6D, 0x00]) }
        switch (b[1], b[2]) {
        case (0xA4, 0x04): return Data([0x90, 0x00])
        case (0xA4, _): return Data([0x6A, 0x82])
        case (0x84, _): return Data([1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x00])
        default: return Data([0x63, 0x00])
        }
    }
}
#endif
#endif
