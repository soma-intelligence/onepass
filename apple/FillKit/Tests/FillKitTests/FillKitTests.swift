import Foundation
import Testing

@testable import FillKit

private func fixture(_ name: String) throws -> FieldSnapshot {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try JSONDecoder().decode(FieldSnapshot.self, from: Data(contentsOf: url))
}

@Suite struct FieldClassifierTests {
    @Test func secureFieldIsPassword() throws {
        #expect(FieldClassifier.kind(try fixture("secure"), above: nil) == .password)
    }

    @Test func textFieldLabelledPasswordInWebViewIsPassword() throws {
        #expect(FieldClassifier.kind(try fixture("webPassword"), above: nil) == .password)
    }

    @Test func fakeLabelOnPlainFieldIsNotPassword() throws {
        #expect(FieldClassifier.kind(try fixture("fakeLabel"), above: nil) == .other)
    }

    @Test func fieldAbovePasswordIsUsername() throws {
        let user = try fixture("username")
        let pass = try fixture("webPassword")
        #expect(FieldClassifier.kind(user, above: nil, below: pass) == .username)
        #expect(FieldClassifier.kind(user, above: nil) == .other)
    }

    @Test func oneTimeCodeByAutocompleteClass() throws {
        #expect(FieldClassifier.kind(try fixture("otp"), above: nil) == .oneTimeCode)
    }

    @Test func labelsAndPlaceholders() {
        var f = FieldSnapshot(role: "AXTextField", placeholder: "Password:", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .password)
        f = FieldSnapshot(role: "AXTextField", label: "Mot de passe *", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .password)
        f = FieldSnapshot(role: "AXTextField", placeholder: "Verification code", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .oneTimeCode)
        f = FieldSnapshot(role: "AXTextField", title: "Password", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .other)
        f = FieldSnapshot(role: "AXTextField", domClasses: ["form-pwd-input"], bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .password)
    }

    private func kind(id: String? = nil, classes: [String] = [], placeholder: String? = nil, role: String = "AXTextField") -> FieldKind {
        FieldClassifier.kind(
            FieldSnapshot(role: role, placeholder: placeholder, domIdentifier: id, domClasses: classes, bundleID: "x"),
            above: nil)
    }

    @Test func oneTimeMarkersMatchWholeTokensOnly() {
        #expect(kind(id: "footprint") == .other)
        #expect(kind(classes: ["hotpink"]) == .other)
        #expect(kind(classes: ["otp-input"]) == .oneTimeCode)
        #expect(kind(id: "otpCode") == .oneTimeCode)
        #expect(kind(id: "login_2fa") == .oneTimeCode)
        #expect(kind(id: "one_time_code") == .oneTimeCode)
    }

    @Test func passwordTokenizer() {
        #expect(kind(id: "passport") == .other)
        #expect(kind(id: "password-confirm") == .password)
        #expect(kind(id: "userPassword") == .password)
        #expect(kind(id: "password1") == .password)
        #expect(kind(id: "mot-de-passe") == .password)
        #expect(kind(id: "mot-de-passeport") == .other)
        #expect(kind(classes: ["pwd"]) == .password)
    }

    @Test func nonASCIIKeywords() {
        #expect(kind(placeholder: "密码") == .password)
        #expect(kind(placeholder: "请输入密码") == .password)
        #expect(kind(placeholder: "비밀번호") == .password)
        #expect(kind(placeholder: "Contraseña") == .password)
        #expect(kind(placeholder: "Contrasen\u{0303}a") == .password)
        #expect(kind(id: "contrasen\u{0303}a") == .password)
        #expect(kind(placeholder: "Your password hint") == .other)
    }

    @Test func secureRoleAloneIsPassword() {
        #expect(kind(role: "AXSecureTextField") == .password)
    }

    @Test func plainFieldWithNonPasswordBelowIsOther() {
        let f = FieldSnapshot(role: "AXTextField", bundleID: "x")
        let below = FieldSnapshot(role: "AXTextField", domIdentifier: "email", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil, below: below) == .other)
    }

    @Test func passwordWinsOverOneTimeCode() {
        let f = FieldSnapshot(role: "AXTextField", domIdentifier: "otp_password", bundleID: "x")
        #expect(FieldClassifier.kind(f, above: nil) == .password)
    }
}

@Suite struct TargetResolverTests {
    @Test func urlWinsOverBundleID() throws {
        let t = TargetResolver.target(for: try fixture("pageWithURL"))
        #expect(t == .url(URL(string: "https://example.com/login")!))
    }

    @Test func noURLFallsBackToApp() throws {
        let t = TargetResolver.target(for: try fixture("appNoURL"))
        #expect(t == .app(bundleID: "com.example.app", windowTitle: "Sign in"))
    }

    @Test func nonWebSchemeFallsBackToApp() {
        let f = FieldSnapshot(bundleID: "a", url: URL(string: "file:///tmp/x.html"))
        #expect(TargetResolver.target(for: f) == .app(bundleID: "a", windowTitle: nil))
    }

    @Test func urlFromSafariIsAURLTarget() {
        let url = URL(string: "https://accounts.google.com/signin")!
        let f = FieldSnapshot(bundleID: "com.apple.Safari", windowTitle: "Google", url: url)
        #expect(TargetResolver.target(for: f) == .url(url))
    }

    /// A native app can put any URL in `AXURL` or `AXDocument`: it never claims a web origin.
    @Test func urlFromANonBrowserAppIsAnAppTarget() {
        let f = FieldSnapshot(
            bundleID: "com.example.notabrowser", windowTitle: "Google",
            url: URL(string: "https://accounts.google.com/signin"))
        #expect(TargetResolver.target(for: f) == .app(bundleID: "com.example.notabrowser", windowTitle: "Google"))
    }

    @Test func nonWebURLFromABrowserIsAnAppTarget() {
        let f = FieldSnapshot(bundleID: "com.google.Chrome", url: URL(string: "file:///tmp/x.html"))
        #expect(TargetResolver.target(for: f) == .app(bundleID: "com.google.Chrome", windowTitle: nil))
    }
}

@Suite struct KnownBrowsersTests {
    @Test func coversTheMainBrowsers() {
        for id in [
            "com.apple.Safari", "com.apple.SafariTechnologyPreview", "com.google.Chrome",
            "com.google.Chrome.beta", "com.google.Chrome.canary", "org.chromium.Chromium",
            "com.microsoft.edgemac", "com.brave.Browser", "com.vivaldi.Vivaldi",
            "com.operasoftware.Opera", "company.thebrowser.Browser", "com.kagi.kagimacOS",
            "org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly",
            "org.torproject.torbrowser", "com.duckduckgo.macos.browser", "app.zen-browser.zen",
        ] {
            #expect(KnownBrowsers.contains(id), "\(id)")
        }
        #expect(!KnownBrowsers.contains("com.tinyspeck.slackmacgap"))
        #expect(!KnownBrowsers.contains(nil))
    }

    /// Bundle ids compare without case, as Launch Services does.
    @Test func comparesWithoutCase() {
        #expect(KnownBrowsers.contains("COM.apple.safari"))
    }
}

@Suite struct FillFlowTests {
    @Test func flowFromUsername() {
        #expect(
            FillFlow.steps(focused: .username, hasPasswordBelow: true, hasTotp: false)
                == [.value(.username), .tab, .value(.password)])
    }

    @Test func flowAddsTotpWhenAsked() {
        #expect(
            FillFlow.steps(focused: .password, hasPasswordBelow: false, hasTotp: true)
                == [.value(.password), .value(.oneTimeCode)])
        #expect(
            FillFlow.steps(focused: .username, hasPasswordBelow: true, hasTotp: true)
                == [.value(.username), .tab, .value(.password), .value(.oneTimeCode)])
    }

    @Test func otherFlows() {
        #expect(FillFlow.steps(focused: .oneTimeCode, hasPasswordBelow: false, hasTotp: true) == [.value(.oneTimeCode)])
        #expect(FillFlow.steps(focused: .other, hasPasswordBelow: true, hasTotp: true) == [])
    }
}

@Suite struct FocusGuardTests {
    @Test func guardHoldsOnSame() {
        #expect(FocusGuard(pid: 10, elementID: "a").holds(pid: 10, elementID: "a"))
    }

    @Test func guardFailsOnOtherPid() {
        #expect(!FocusGuard(pid: 10, elementID: "a").holds(pid: 11, elementID: "a"))
    }

    @Test func guardFailsOnOtherElement() {
        #expect(!FocusGuard(pid: 10, elementID: "a").holds(pid: 10, elementID: "b"))
    }
}

@Suite struct FieldSnapshotCodingTests {
    @Test func roundTrip() throws {
        let f = FieldSnapshot(
            role: "AXTextField", subrole: "AXSecureTextField", title: "t", placeholder: "p",
            label: "l", domIdentifier: "id", domClasses: ["a", "b"],
            frame: CGRect(x: 1, y: 2, width: 3, height: 4), pid: 42, bundleID: "com.x",
            windowTitle: "w", url: URL(string: "https://example.com/"))
        let data = try JSONEncoder().encode(f)
        #expect(try JSONDecoder().decode(FieldSnapshot.self, from: data) == f)
    }

    @Test func missingBundleIDThrows() {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(FieldSnapshot.self, from: Data(#"{"role":"AXTextField"}"#.utf8))
        }
    }
}
