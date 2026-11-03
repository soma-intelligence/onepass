import Foundation
import OnePassCore

/// The choices of the "possible duplicates" section of the import sheet: one per item of the export
/// that matches a vault item (`FfiImportSummary.duplicates`), starting from the core's suggestion
/// (skip an exact duplicate, merge a near one). Bulk actions set every row at once, so a 500-item
/// import is one tap. Only the rows the user changed are sent back (`decisions`); the core applies
/// the suggestion to the others.
public struct ImportDuplicateChoices: Equatable, Sendable {
    /// The pairs, in export order.
    public private(set) var rows: [FfiImportDuplicate]
    private var chosen: [UInt32: FfiImportChoice] = [:]

    public init(_ duplicates: [FfiImportDuplicate] = []) {
        rows = duplicates
    }

    /// The pairs of a new preview (another vault, another file). A choice made on a pair that is still
    /// there (same export position, same vault item) is kept.
    public mutating func update(_ duplicates: [FfiImportDuplicate]) {
        let kept = Dictionary(uniqueKeysWithValues: duplicates.map { ($0.index, $0.existing.id) })
        let before = Dictionary(uniqueKeysWithValues: rows.map { ($0.index, $0.existing.id) })
        chosen = chosen.filter { index, _ in kept[index] != nil && kept[index] == before[index] }
        rows = duplicates
    }

    public var isEmpty: Bool { rows.isEmpty }
    public var count: Int { rows.count }

    /// The choice of the row at export position `index`: the user's, else the suggestion.
    public func choice(for index: UInt32) -> FfiImportChoice {
        if let c = chosen[index] { return c }
        return rows.first { $0.index == index }?.suggested ?? .merge
    }

    public mutating func set(_ choice: FfiImportChoice, for index: UInt32) {
        guard let row = rows.first(where: { $0.index == index }) else { return }
        chosen[index] = choice == row.suggested ? nil : choice
    }

    /// "Tout fusionner", "Tout ignorer", "Tout importer".
    public mutating func setAll(_ choice: FfiImportChoice) {
        for row in rows { set(choice, for: row.index) }
    }

    /// Back to the suggestions.
    public mutating func resetToSuggested() {
        chosen = [:]
    }

    /// Every row holds `choice`.
    public func all(_ choice: FfiImportChoice) -> Bool {
        !rows.isEmpty && rows.allSatisfy { self.choice(for: $0.index) == choice }
    }

    /// How many rows hold `choice`.
    public func count(of choice: FfiImportChoice) -> Int {
        rows.count(where: { self.choice(for: $0.index) == choice })
    }

    /// Rows that are exact duplicates (nothing would change by merging them).
    public var exactCount: Int { rows.count(where: { $0.exact }) }

    /// What `VaultSession.importItems` takes: the rows that differ from the suggestion.
    public var decisions: [FfiImportDecision] {
        rows.compactMap { row in
            chosen[row.index].map { FfiImportDecision(index: row.index, choice: $0) }
        }
    }
}
