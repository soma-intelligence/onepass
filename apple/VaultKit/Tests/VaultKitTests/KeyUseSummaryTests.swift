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
        field: String = "", device: String = "", agoSeconds: Int64, count: UInt32
    ) -> FfiKeyUse {
        let at = Int64(now.timeIntervalSince1970) - agoSeconds
        return FfiKeyUse(
            channel: channel, action: action, deviceName: device, client: client, field: field,
            firstAt: at, lastAt: at, count: count)
    }

    @Test func header_for_recent_and_month_count() {
        let day: Int64 = 86_400
        // Not sorted on purpose: the newest entry gives the relative part. The 40-day-old entry
        // is outside the month, so 10 + 4 = 14.
        let uses = [
            Self.use(.cli, agoSeconds: 5 * day, count: 4),
            Self.use(.mcp, agoSeconds: 40 * day, count: 7),
            Self.use(.app, agoSeconds: 2 * 3600, count: 10),
        ]
        let header = KeyUseSummary.header(uses, now: Self.now, locale: Self.fr)
        // The formatter puts a no-break space between the number and its unit.
        #expect(header == "Utilisée il y a 2\u{A0}h · 14 fois ce mois")
    }

    @Test func header_without_use_this_month_has_no_count() {
        let uses = [Self.use(agoSeconds: 45 * 86_400, count: 3)]
        let header = KeyUseSummary.header(uses, now: Self.now, locale: Self.fr)
        #expect(header?.hasPrefix("Utilisée ") == true)
        #expect(header?.contains("·") == false)
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
