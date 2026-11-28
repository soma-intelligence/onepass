import Foundation

/// Text of an item's "Utilisation" section (key-use log, spec 2026-11-14): the one-line summary and
/// one line per entry. Pure, so the app and the tests share it. Client, field and device names come
/// from the log as stored (the client's own words, untrusted): they are joined as plain text, and the
/// app shows the result with `Text(verbatim:)`, never as Markdown.
public enum KeyUseSummary {
    /// "Utilisée il y a 2 h · 365 fois depuis mars": the newest use relative to `now`, then the sum
    /// of the counts of every entry since the month of the earliest first use. An entry coalesces
    /// every use of one client on one device for up to a year, so its count runs from its
    /// `firstAt`: the log cannot tell a count for this month, only one since that month. The year
    /// is named when it is not the year of `now` ("depuis mars 2026"). Nil when the log is empty
    /// (the section is hidden). `locale` formats the dates; it defaults to the language the strings
    /// are read in.
    public static func header(_ uses: [FfiKeyUse], now: Date, locale: Locale? = nil) -> String? {
        guard let newest = uses.map(\.lastAt).max(), let earliest = uses.map(\.firstAt).min() else {
            return nil
        }
        let locale = locale ?? Locale(identifier: VaultKitStrings.language)
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        // `.short`, not `.abbreviated`: in French the abbreviated style drops "il y a" ("-2 h").
        formatter.unitsStyle = .short
        formatter.dateTimeStyle = .named
        // Another device's clock may run ahead: never "dans 3 min".
        let last = min(Date(timeIntervalSince1970: TimeInterval(newest)), now)
        let relative = formatter.localizedString(for: last, relativeTo: now)
        let total = uses.reduce(0) { $0 + Int($1.count) }
        let start = min(Date(timeIntervalSince1970: TimeInterval(earliest)), now)
        let times = String(localized: "keyUse.times \(total)", bundle: VaultKitStrings.bundle)
        let since = String(
            localized: "keyUse.countSince \(times) \(monthName(start, now: now, locale: locale))",
            bundle: VaultKitStrings.bundle)
        return [String(localized: "keyUse.lastUsed \(relative)", bundle: VaultKitStrings.bundle), since]
            .joined(separator: " · ")
    }

    /// "mars", or "mars 2026" when `date` is not in the year of `now`.
    static func monthName(_ date: Date, now: Date, locale: Locale) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.locale = locale
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.calendar = calendar
        let sameYear = calendar.component(.year, from: date) == calendar.component(.year, from: now)
        formatter.setLocalizedDateFormatFromTemplate(sameYear ? "MMMM" : "MMMMy")
        return formatter.string(from: date)
    }

    /// "Claude Code · MCP · révélé Mot de passe · MacBook Air · ×3": client, channel, action and
    /// field, device, count. An empty part is left out, so no separator is ever doubled.
    public static func row(_ use: FfiKeyUse) -> String {
        let action = [actionName(use.action), use.field].filter { !$0.isEmpty }.joined(separator: " ")
        return [use.client, channelName(use.channel), action, use.deviceName, "×\(use.count)"]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }

    /// Product names, the same in every language (except the Mac fill label).
    public static func channelName(_ channel: FfiKeyUseChannel) -> String {
        switch channel {
        case .app: "App"
        case .autoFill: "AutoFill"
        case .cli: "CLI"
        case .mcp: "MCP"
        case .sshAgent: "SSH"
        case .desktopFill: String(localized: "keyUse.channel.desktopFill", bundle: VaultKitStrings.bundle)
        }
    }

    public static func actionName(_ action: FfiKeyUseAction) -> String {
        switch action {
        case .revealed: String(localized: "keyUse.action.revealed", bundle: VaultKitStrings.bundle)
        case .copied: String(localized: "keyUse.action.copied", bundle: VaultKitStrings.bundle)
        case .injected: String(localized: "keyUse.action.injected", bundle: VaultKitStrings.bundle)
        case .totp: String(localized: "keyUse.action.totp", bundle: VaultKitStrings.bundle)
        case .signed: String(localized: "keyUse.action.signed", bundle: VaultKitStrings.bundle)
        case .filled: String(localized: "keyUse.action.filled", bundle: VaultKitStrings.bundle)
        }
    }
}
