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
        #expect(FieldClassifier.kind(try fixture("fakeLabel"), above: nil) != .password)
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
