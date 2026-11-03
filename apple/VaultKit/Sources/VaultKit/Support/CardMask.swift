import Foundation

/// A credit card shown by its last four digits, "•••• 4242", so cards tell apart at a glance in
/// lists and the item header. The core hands the four digits in `FfiItemSummary.cardLast4` (never
/// more of the number); the mask is the same in every language.
public enum CardMask {
    /// "•••• 4242": a few dots, never a full-length row of them.
    public static func text(_ last4: String) -> String {
        "\u{2022}\u{2022}\u{2022}\u{2022} \(last4)"
    }
}

extension FfiItemSummary {
    /// "•••• 4242" for a credit card whose number has at least 8 digits, nil otherwise.
    public var cardMask: String? {
        guard let last4 = cardLast4, !last4.isEmpty else { return nil }
        return CardMask.text(last4)
    }

    /// The line under the title in a list: the core's subtitle (a login's username), or a card's
    /// mask when it has none. Empty when there is neither: the row then shows the category.
    public var listSubtitle: String {
        if !subtitle.isEmpty { return subtitle }
        return cardMask ?? ""
    }
}
