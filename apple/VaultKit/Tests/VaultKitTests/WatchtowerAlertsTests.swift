import Foundation
import Testing

@testable import VaultKit

@Suite("Watchtower alerts and exclusions")
struct WatchtowerAlertsTests {
    private func report(_ checks: [String: [String]]) -> FfiWatchtowerReport {
        FfiWatchtowerReport(
            score: 80, itemsAnalyzed: 3,
            checks: checks.map { FfiWatchtowerCheck(check: $0.key, findings: UInt32($0.value.count), itemIds: $0.value) },
            strength: [0, 0, 0, 0, 0], pwned: .checked, missingPrefixes: [], sitesChecked: false)
    }

    @Test func firstReportIsRememberedWithoutAlerting() {
        let (alerts, memory) = WatchtowerAlerts.diff(report(["compromised": ["a"]]), remembered: nil)
        #expect(alerts.isEmpty)
        #expect(memory.count == 1)
    }

    @Test func onlyNewAlertableFindingsAlert() {
        let (_, memory) = WatchtowerAlerts.diff(report(["compromised": ["a"], "weak": ["a"]]), remembered: nil)
        let next = report([
            "compromised": ["a", "b"], "expiring": ["c"], "weak": ["a", "d"], "reused": ["e", "f"],
        ])
        let (alerts, updated) = WatchtowerAlerts.diff(next, remembered: memory)
        #expect(alerts == [WatchtowerAlerts.Alert(check: "compromised", count: 1),
                           WatchtowerAlerts.Alert(check: "expiring", count: 1)])
        // Seen once, never again; a fixed finding leaves the memory.
        let (again, _) = WatchtowerAlerts.diff(next, remembered: updated)
        #expect(again.isEmpty)
        let (fixed, shrunk) = WatchtowerAlerts.diff(report([:]), remembered: updated)
        #expect(fixed.isEmpty && shrunk.isEmpty)
    }

    @Test func memoryHoldsNoItemID() {
        let (_, memory) = WatchtowerAlerts.diff(report(["expired": ["0123456789abcdef0123456789abcdef"]]), remembered: nil)
        #expect(memory.allSatisfy { !$0.contains("0123456789abcdef") && $0.count == 16 })
    }

    @Test func notificationTextNamesNoItem() {
        let text = WatchtowerAlerts.body(for: [.init(check: "compromised", count: 2), .init(check: "expired", count: 1)])
        #expect(text.contains("2"))
        #expect(!text.isEmpty)
    }

    @Test func exclusionsToggleWithoutDuplicates() {
        var ids = ["passkey_available"]
        WatchtowerExclusions.set("weak", excluded: true, in: &ids)
        WatchtowerExclusions.set("weak", excluded: true, in: &ids)
        #expect(ids == ["passkey_available", "weak"])
        WatchtowerExclusions.set("passkey_available", excluded: false, in: &ids)
        #expect(ids == ["weak"])
    }

    @Test func findingsOfAnItemComeFromTheReport() {
        let r = report(["weak": ["a", "b"], "insecure_url": ["a"], "reused": ["b"]])
        #expect(WatchtowerExclusions.checks(of: "a", in: r) == ["insecure_url", "weak"])
        #expect(WatchtowerExclusions.checks(of: "z", in: r).isEmpty)
    }
}
