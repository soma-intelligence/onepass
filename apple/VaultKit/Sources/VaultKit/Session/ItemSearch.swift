import Foundation

/// Local search over item summaries (no secret is searched): title, subtitle, primary URL and tags,
/// case and accent insensitive; every word of the query must appear.
public enum ItemSearch {
    /// Folded form used on both sides: NFC, then case and diacritics removed.
    static func fold(_ text: String) -> String {
        text.precomposedStringWithCanonicalMapping
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }

    public static func words(_ query: String) -> [String] {
        fold(query).split(whereSeparator: { $0.isWhitespace }).map(String.init)
    }

    public static func matches(_ item: FfiItemSummary, words: [String]) -> Bool {
        guard !words.isEmpty else { return true }
        var parts = [item.title, item.subtitle]
        if let url = item.primaryUrl { parts.append(url) }
        parts.append(contentsOf: item.tags)
        let haystack = fold(parts.joined(separator: "\n"))
        return words.allSatisfy { haystack.contains($0) }
    }

    public static func filter(_ items: [FfiItemSummary], query: String) -> [FfiItemSummary] {
        let words = words(query)
        guard !words.isEmpty else { return items }
        return items.filter { matches($0, words: words) }
    }

    /// How well an item answers `words` (lower is better): the title starting with the query, then
    /// a word of the title starting with each word of it, then the title holding them, then only
    /// another field (subtitle, site, tag) holding them.
    public static func rank(_ item: FfiItemSummary, words: [String]) -> Int {
        guard let first = words.first else { return 0 }
        let title = fold(item.title)
        let phrase = words.joined(separator: " ")
        if title.hasPrefix(phrase) { return 0 }
        let titleWords = title.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        if words.allSatisfy({ word in titleWords.contains { $0.hasPrefix(word) } }) { return 1 }
        if title.contains(first), words.allSatisfy(title.contains) { return 2 }
        return 3
    }

    /// The items matching `query`, best answers first, then in the given order (title for the
    /// search screen). An empty query keeps every item in its order.
    public static func ranked(_ items: [FfiItemSummary], query: String) -> [FfiItemSummary] {
        let words = words(query)
        guard !words.isEmpty else { return items }
        return items.enumerated()
            .filter { matches($0.element, words: words) }
            .map { (rank: rank($0.element, words: words), offset: $0.offset, item: $0.element) }
            .sorted { $0.rank != $1.rank ? $0.rank < $1.rank : $0.offset < $1.offset }
            .map(\.item)
    }
}

/// The searches typed on this device during the session, newest first: memory only, emptied on
/// lock with the recent items (a search names the sites one has, it is never written anywhere).
public enum RecentSearches {
    public static let limit = 8

    /// `query` added at the front (trimmed; a search already there moves up, whatever its case or
    /// accents), the oldest dropped past `limit`. Blank or one character: nothing changes.
    public static func adding(_ query: String, to list: [String]) -> [String] {
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count >= 2 else { return list }
        let key = ItemSearch.fold(text)
        var out = list.filter { ItemSearch.fold($0) != key }
        out.insert(text, at: 0)
        return Array(out.prefix(limit))
    }
}
