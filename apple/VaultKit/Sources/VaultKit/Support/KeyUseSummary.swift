import Foundation

/// Text of an item's "Utilisation" section (key-use log, spec 2026-11-14): the one-line summary and
/// one line per entry. Pure, so the app and the tests share it. Client, field and device names come
/// from the log as stored (the client's own words, untrusted): they are joined as plain text, and the
/// app shows the result with `Text(verbatim:)`, never as Markdown.
public enum KeyUseSummary {
    /// The window of "N fois ce mois": the last 30 days, not the calendar month, so the count does
    /// not drop to zero on the first of the month.
    static let monthWindow: TimeInterval = 30 * 86_400

    /// "Utilisée il y a 2 h · 14 fois ce mois": the newest use relative to `now`, then the sum of
    /// the counts of the entries used within the last 30 days (left out when none). Nil when the log
    /// is empty (the section is hidden). `locale` formats the relative date; it defaults to the
    /// language the strings are read in.
    public static func header(_ uses: [FfiKeyUse], now: Date, locale: Locale? = nil) -> String? {
        guard let newest = uses.map(\.lastAt).max() else { return nil }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale ?? Locale(identifier: VaultKitStrings.language)
        // `.short`, not `.abbreviated`: in French the abbreviated style drops "il y a" ("-2 h").
        formatter.unitsStyle = .short
        formatter.dateTimeStyle = .named
        // Another device's clock may run ahead: never "dans 3 min".
        let last = min(Date(timeIntervalSince1970: TimeInterval(newest)), now)
        let relative = formatter.localizedString(for: last, relativeTo: now)
        var parts = [String(localized: "keyUse.lastUsed \(relative)", bundle: VaultKitStrings.bundle)]
        let since = Int64(now.addingTimeInterval(-monthWindow).timeIntervalSince1970)
        let month = uses.filter { $0.lastAt >= since }.reduce(0) { $0 + Int($1.count) }
        if month > 0 {
            parts.append(String(localized: "keyUse.monthCount \(month)", bundle: VaultKitStrings.bundle))
        }
        return parts.joined(separator: " · ")
    }

    /// "Claude Code · MCP · révélé Mot de passe · MacBook Air · ×3": client, channel, action and
    /// field, device, count. An empty part is left out, so no separator is ever doubled.
    public static func row(_ use: FfiKeyUse) -> String {
        let action = [actionName(use.action), use.field].filter { !$0.isEmpty }.joined(separator: " ")
        return [use.client, channelName(use.channel), action, use.deviceName, "×\(use.count)"]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }

    /// Product names, the same in every language.
    public static func channelName(_ channel: FfiKeyUseChannel) -> String {
        switch channel {
        case .app: "App"
        case .autoFill: "AutoFill"
        case .cli: "CLI"
        case .mcp: "MCP"
        case .sshAgent: "SSH"
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
