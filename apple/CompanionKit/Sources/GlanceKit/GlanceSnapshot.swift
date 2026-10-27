import Foundation

public struct GlanceTint: Codable, Sendable, Hashable {
    public var red: Double
    public var green: Double
    public var blue: Double

    public init(red: Double, green: Double, blue: Double) {
        self.red = red
        self.green = green
        self.blue = blue
    }
}

public struct GlanceItem: Codable, Sendable, Hashable, Identifiable {
    public var vaultID: String
    public var itemID: String
    public var title: String
    public var symbol: String
    public var tint: GlanceTint

    public init(vaultID: String, itemID: String, title: String, symbol: String, tint: GlanceTint) {
        self.vaultID = vaultID
        self.itemID = itemID
        self.title = title
        self.symbol = symbol
        self.tint = tint
    }

    public var id: String { "\(vaultID):\(itemID)" }
    public var link: OnePassLink { .item(vaultID: vaultID, itemID: itemID) }
}

public struct GlanceCode: Codable, Sendable, Hashable {
    public var start: Date
    public var end: Date
    public var code: String

    public init(start: Date, end: Date, code: String) {
        self.start = start
        self.end = end
        self.code = code
    }
}

public struct GlanceCodes: Codable, Sendable, Hashable, Identifiable {
    public var item: GlanceItem
    public var period: Int
    public var codes: [GlanceCode]

    public init(item: GlanceItem, period: Int, codes: [GlanceCode]) {
        self.item = item
        self.period = period
        self.codes = codes
    }

    public var id: String { item.id }

    /// The code with `start <= date < end`, or nil (callers treat nil as "needs refresh").
    public func code(at date: Date) -> GlanceCode? {
        codes.first { $0.start <= date && date < $0.end }
    }
}

public struct GlanceSnapshot: Codable, Sendable, Hashable {
    public var generatedAt: Date
    public var validUntil: Date
    public var favorites: [GlanceItem]
    public var codes: [GlanceCodes]

    public init(generatedAt: Date, validUntil: Date, favorites: [GlanceItem], codes: [GlanceCodes]) {
        self.generatedAt = generatedAt
        self.validUntil = validUntil
        self.favorites = favorites
        self.codes = codes
    }
}
