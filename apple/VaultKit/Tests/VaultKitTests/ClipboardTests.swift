import Foundation
import Testing
#if canImport(AppKit)
import AppKit
#endif

@testable import VaultKit

@MainActor
@Suite("Clipboard")
struct ClipboardTests {
    @Test func clipboardClearsAfterNinetySecondsIfUnchanged() {
        let pasteboard = FakePasteboard()
        let clock = FakeClock()
        let clipboard = Clipboard(pasteboard: pasteboard, clock: clock)
        clipboard.copy("motdepasse-fictif", concealed: true)
        #expect(pasteboard.snapshot.contents == "motdepasse-fictif")
        #expect(pasteboard.snapshot.concealed)
        #expect(pasteboard.snapshot.expiresAfter == 90)

        clock.advance(89)
        clipboard.clearIfExpired()
        #expect(pasteboard.snapshot.contents == "motdepasse-fictif")

        clock.advance(1)
        clipboard.clearIfExpired()
        #expect(pasteboard.snapshot.contents == nil)
    }

    @Test func clipboardKeepsWhatAnotherAppCopied() {
        let pasteboard = FakePasteboard()
        let clock = FakeClock()
        let clipboard = Clipboard(pasteboard: pasteboard, clock: clock)
        clipboard.copy("motdepasse-fictif", concealed: true)
        pasteboard.externalWrite("adresse copiée ailleurs")
        clock.advance(91)
        clipboard.clearIfExpired()
        #expect(pasteboard.snapshot.contents == "adresse copiée ailleurs")
    }

    @Test func newCopyRestartsTheDelay() {
        let pasteboard = FakePasteboard()
        let clock = FakeClock()
        let clipboard = Clipboard(pasteboard: pasteboard, clock: clock)
        clipboard.copy("premier", concealed: false)
        clock.advance(60)
        clipboard.copy("second", concealed: false)
        clock.advance(60)
        clipboard.clearIfExpired()
        #expect(pasteboard.snapshot.contents == "second")
        clock.advance(30)
        clipboard.clearIfExpired()
        #expect(pasteboard.snapshot.contents == nil)
    }

    #if os(macOS)
    /// Real `NSPasteboard`, on a private named pasteboard (never the user's).
    @Test func systemPasteboardMarksConcealedAndClearsIfUnchanged() {
        let name = NSPasteboard.Name("me.somalabs.onepass.tests.\(UUID().uuidString)")
        let board = NSPasteboard(name: name)
        defer { board.releaseGlobally() }
        let system = SystemPasteboard(name: name)

        system.write("motdepasse-fictif", concealed: true, expiresAfter: 90)
        #expect(board.string(forType: .string) == "motdepasse-fictif")
        #expect(board.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true)
        system.clearIfUnchanged()
        #expect(board.string(forType: .string) == nil)

        system.write("identifiant-fictif", concealed: false, expiresAfter: 90)
        #expect(board.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == false)
        board.clearContents()
        board.setString("copié ailleurs", forType: .string)
        system.clearIfUnchanged()
        #expect(board.string(forType: .string) == "copié ailleurs")
    }
    #endif
}
