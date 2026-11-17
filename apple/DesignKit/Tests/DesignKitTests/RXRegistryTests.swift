import SwiftUI
import Testing
@testable import DesignKit

/// The Penpot registry of the RX components. `dbridge drift` (Soma_Tools/design-bridge) reads the
/// same declarations from source and compares them with Penpot; these tests keep them well formed.
@Suite("RX Penpot registry")
struct RXRegistryTests {
    /// Every RX building block that draws a Penpot main component.
    static let mapped: [(String, PenpotComponent)] = [
        ("GlassButton", GlassButton.penpot),
        ("ColorDisc", ColorDisc.penpot),
        ("RXItemRow", RXItemRow<EmptyView>.penpot),
        ("RXMenuRow", RXMenuRow.penpot),
        ("RXCard", RXCard<EmptyView>.penpot),
        ("RXCardHeader", RXCardHeader.penpot),
        ("RXStatTile", RXStatTile.penpot),
        ("QuickActionLabel", QuickActionLabel.penpot),
        ("QuickActionRow", QuickActionRow<EmptyView>.penpot),
        ("PlanCard", PlanCard.penpot),
        ("PerkTile", PerkTile.penpot),
    ]

    @Test(arguments: mapped.map(\.0))
    func pathIsCanonical(_ type: String) throws {
        let c = try #require(Self.mapped.first { $0.0 == type }?.1)
        #expect(!c.path.isEmpty)
        // `dbridge` matches canonical paths: no spaces around the separators, no empty segment.
        #expect(!c.path.contains(" /") && !c.path.contains("/ "))
        #expect(!c.path.split(separator: "/", omittingEmptySubsequences: false).contains(""))
    }

    @Test(arguments: mapped.map(\.0))
    func propsNameALayerOrAnAxis(_ type: String) throws {
        let c = try #require(Self.mapped.first { $0.0 == type }?.1)
        for (key, prop) in c.props {
            #expect(!key.isEmpty)
            switch prop {
            case .text(let layer), .swap(let layer), .fill(let layer):
                #expect(!layer.isEmpty, "\(type).\(key)")
            case .variant(let axis, let values):
                #expect(!axis.isEmpty, "\(type).\(key)")
                #expect(!values.isEmpty && Set(values).count == values.count, "\(type).\(key)")
            }
        }
    }

    @Test func oneViewPerPath() {
        let paths = Self.mapped.map(\.1.path)
        #expect(Set(paths).count == paths.count)
    }
}
