import Foundation
import Testing

@testable import VaultKit

@Suite("KeyUseSummary")
struct KeyUseSummaryTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let fr = Locale(identifier: "fr_FR")

    static func use(
        _ channel: FfiKeyUseChannel = .app, _ action: FfiKeyUseAction = .copied, client: String = "",
        field: String = "", device: String = "", firstAgoSeconds: Int64? = nil, agoSeconds: Int64,
        count: UInt32
    ) -> FfiKeyUse {
        let base = Int64(now.timeIntervalSince1970)
        let at = base - agoSeconds
        return FfiKeyUse(
            channel: channel, action: action, deviceName: device, client: client, field: field,
            firstAt: base - (firstAgoSeconds ?? agoSeconds), lastAt: at, count: count)
    }

    // `now` is 2027-01-15 08:00 UTC; every date below sits well inside its month, whatever the
    // machine's time zone.
    static let day: Int64 = 86_400

    @Test func header_counts_every_use_since_the_first_month() {
        // Not sorted on purpose: the newest entry gives the relative part. An entry coalesces
        // forever, so its count runs from its first use (300 days ago, March 2026), not this
        // month: 365 + 7 + 4 = 376 uses since March 2026.
        let uses = [
            Self.use(.cli, agoSeconds: 5 * Self.day, count: 4),
            Self.use(.mcp, firstAgoSeconds: 100 * Self.day, agoSeconds: 40 * Self.day, count: 7),
            Self.use(.sshAgent, .signed, firstAgoSeconds: 300 * Self.day, agoSeconds: 2 * 3600, count: 365),
        ]
        let header = KeyUseSummary.header(uses, now: Self.now, locale: Self.fr)
        // The formatter puts a no-break space between the number and its unit.
        #expect(header == "Utilisée il y a 2\u{A0}h · 376 fois depuis mars 2026")
    }

    @Test func header_since_this_year_names_the_month_only() {
        let uses = [Self.use(firstAgoSeconds: 10 * Self.day, agoSeconds: 2 * 3600, count: 1)]
        let header = KeyUseSummary.header(uses, now: Self.now, locale: Self.fr)
        #expect(header == "Utilisée il y a 2\u{A0}h · 1 fois depuis janvier")
    }

    @Test func header_counts_uses_older_than_a_month() {
        let uses = [Self.use(agoSeconds: 50 * Self.day, count: 3)]
        let header = KeyUseSummary.header(uses, now: Self.now, locale: Self.fr)
        #expect(header?.hasPrefix("Utilisée ") == true)
        #expect(header?.hasSuffix(" · 3 fois depuis novembre 2026") == true)
    }

    @Test func header_empty_is_nil() {
        #expect(KeyUseSummary.header([], now: Self.now, locale: Self.fr) == nil)
    }

    @Test func row_has_every_part_in_order() {
        let use = Self.use(
            .mcp, .revealed, client: "Claude Code", field: "Mot de passe", device: "MacBook Air",
            agoSeconds: 60, count: 3)
        #expect(KeyUseSummary.row(use) == "Claude Code · MCP · révélé Mot de passe · MacBook Air · ×3")
    }

    @Test func row_omits_empty_parts() {
        let use = Self.use(.sshAgent, .signed, agoSeconds: 60, count: 50)
        #expect(KeyUseSummary.row(use) == "SSH · signé · ×50")
    }

    @Test func channel_names() {
        let names = [FfiKeyUseChannel.app, .autoFill, .cli, .mcp, .sshAgent].map(KeyUseSummary.channelName)
        #expect(names == ["App", "AutoFill", "CLI", "MCP", "SSH"])
    }

    @Test func action_names_in_french() {
        let names = [FfiKeyUseAction.revealed, .copied, .injected, .totp, .signed, .filled].map(KeyUseSummary.actionName)
        #expect(names == ["révélé", "copié", "injecté", "code", "signé", "rempli"])
    }
}
