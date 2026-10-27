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
}
