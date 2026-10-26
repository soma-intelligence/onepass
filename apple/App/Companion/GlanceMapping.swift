import DesignKit
import Foundation
import GlanceKit
import VaultKit

/// Converts the core's widget snapshot into the GlanceKit model the widget extension reads. The
/// category symbol and tint come from DesignKit here, so the extension needs neither the core
/// nor DesignKit.
enum GlanceMapping {
    /// `itemTypes` gives the type of a code's item (the core sends it with favorites only); an
    /// unknown item falls back to the Login look.
    static func snapshot(_ ffi: FfiGlanceSnapshot, itemTypes: [String: FfiItemType] = [:]) -> GlanceSnapshot {
        var types = itemTypes
        for favorite in ffi.favorites { types[favorite.itemId] = favorite.itemType }
        let favorites = ffi.favorites.map {
            item(vaultID: $0.vaultId, itemID: $0.itemId, title: $0.title, type: $0.itemType)
        }
        let codes = ffi.codes.map { entry in
            let period = max(1, Int(entry.period))
            return GlanceCodes(
                item: item(
                    vaultID: entry.vaultId, itemID: entry.itemId, title: entry.title,
                    type: types[entry.itemId] ?? .login),
                period: period,
                codes: entry.codes.map { code in
                    let start = Date(timeIntervalSince1970: TimeInterval(code.start))
                    return GlanceCode(start: start, end: start.addingTimeInterval(TimeInterval(period)), code: code.code)
                })
        }
        return GlanceSnapshot(
            generatedAt: Date(timeIntervalSince1970: TimeInterval(ffi.generatedAt)),
            validUntil: Date(timeIntervalSince1970: TimeInterval(ffi.validUntil)),
            favorites: favorites, codes: codes)
    }

    private static func item(vaultID: String, itemID: String, title: String, type: FfiItemType) -> GlanceItem {
        let category = ItemCategory.of(type)
        return GlanceItem(
            vaultID: vaultID, itemID: itemID, title: title, symbol: category.symbol, tint: tint(category.hex))
    }

    static func tint(_ hex: UInt32) -> GlanceTint {
        GlanceTint(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255)
    }
}
