import Foundation
import Testing

@testable import VaultKit

/// The texts the Profil computes: short account ID, sync line, unlock line, top Watchtower issues
/// and the account kind (spec 2026-11-14-profile-account-security, sections 3.2 and 3.3).
@Suite("Profile facts")
struct ProfileFactsTests {
    private func check(_ id: String, _ findings: UInt32) -> FfiWatchtowerCheck {
        FfiWatchtowerCheck(check: id, findings: findings, itemIds: [])
    }

    private func report(_ checks: [FfiWatchtowerCheck]) -> FfiWatchtowerReport {
        FfiWatchtowerReport(
            score: 72, itemsAnalyzed: 40, checks: checks,
            strength: [0, 0, 0, 0, 0], pwned: .checked, missingPrefixes: [], sitesChecked: false)
    }

    @Test func shortIDKeepsFourAndFour() {
        #expect(ProfileFacts.shortID("0123456789abcdef0123456789abcdef") == "0123\u{2026}cdef")
    }

    @Test func shortIDOfShortIDIsUnchanged() {
        #expect(ProfileFacts.shortID("abc123") == "abc123")
        #expect(ProfileFacts.shortID("abcdef123456") == "abcdef123456")
    }

    @Test func shortIDOfNilIsNil() {
        #expect(ProfileFacts.shortID(nil) == nil)
        #expect(ProfileFacts.shortID("") == nil)
    }

    @Test func syncLineIdleWithDateAddsRelativeTime() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let line = ProfileFacts.syncLine(
            .idle(lastSync: now.addingTimeInterval(-180)), now: now, locale: Locale(identifier: "en_US"))
        #expect(line.hasPrefix(SyncStatus.idle(lastSync: nil).label))
        #expect(line.contains("3 min"))
        #expect(line.contains(" \u{00B7} "))
    }

    @Test func syncLineWithoutDateIsLabelOnly() {
        #expect(ProfileFacts.syncLine(.idle(lastSync: nil), now: .now) == SyncStatus.idle(lastSync: nil).label)
        #expect(ProfileFacts.syncLine(.disabled, now: .now) == SyncStatus.disabled.label)
        #expect(ProfileFacts.syncLine(.offline, now: .now) == SyncStatus.offline.label)
    }

    @Test func unlockLineJoinsBiometryAndDelay() {
        #expect(
            ProfileFacts.unlockLine(biometry: "Face ID", delay: .fiveMinutes)
                == "Face ID \u{00B7} \(AutoLockDelay.fiveMinutes.label)")
    }

    @Test func unlockLineWithoutBiometryIsDelayOnly() {
        #expect(ProfileFacts.unlockLine(biometry: nil, delay: .immediately) == AutoLockDelay.immediately.label)
    }

    @Test func topIssuesKeepsTwoLargestNonZeroInGivenOrderOnTies() {
        let report = report([
            check("weak", 2), check("reused", 3), check("insecure_url", 2), check("compromised", 0),
        ])
        let issues = ProfileFacts.topIssues(report, among: ["compromised", "reused", "weak", "insecure_url"])
        #expect(issues == [.init(check: "reused", findings: 3), .init(check: "weak", findings: 2)])
    }

    @Test func topIssuesIgnoresChecksOutsideTheList() {
        let issues = ProfileFacts.topIssues(report([check("passkey_available", 9), check("weak", 1)]), among: ["weak"])
        #expect(issues == [.init(check: "weak", findings: 1)])
    }

    @Test func topIssuesOfNilReportIsEmpty() {
        #expect(ProfileFacts.topIssues(nil, among: ["weak"]).isEmpty)
    }

    @Test func kindLabelFollowsKind() {
        let personal = ProfileFacts.kindLabel(.personal)
        #expect(!personal.isEmpty)
        #expect(personal != ProfileFacts.kindLabel(.business))
        #expect(ProfileFacts.kindLabel(.managed(serverUrl: "https://x", orgId: "ab")) != personal)
    }

    /// Suggestions (a passkey or 2FA a site offers) are not problems: the Profil never lists them.
    @Test func problemChecksLeaveOutSuggestions() {
        #expect(!ProfileFacts.problemChecks.contains("passkey_available"))
        #expect(!ProfileFacts.problemChecks.contains("missing_2fa"))
        #expect(ProfileFacts.problemChecks.starts(with: ["compromised", "breached_site", "provider_exposed", "reused", "weak"]))
    }
}
