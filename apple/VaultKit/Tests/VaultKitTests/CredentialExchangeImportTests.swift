import AuthenticationServices
import CryptoKit
import Foundation
import Testing

@testable import VaultKit

/// Passkeys handed over by another app through the system's Credential Exchange (Passwords >
/// Export to OnePass, iOS and macOS 26): `CredentialExchangeImport` turns the system's data into the
/// CXF JSON the core already imports, and the imported passkey signs like one created by a site.
@MainActor
@Suite("Credential Exchange import")
struct CredentialExchangeImportTests {
    private static let key = P256.Signing.PrivateKey()
    private static let credentialID = Data([1, 2, 3, 250, 99, 7])
    private static let created = Date(timeIntervalSince1970: 1_700_000_000.75)

    private static func exported() -> ASExportedCredentialData {
        let passkey = ASImportableCredential.Passkey(
            credentialID: credentialID, relyingPartyIdentifier: "webauthn.io", userName: "quentin",
            userDisplayName: "Quentin", userHandle: Data([9, 8, 7]), key: key.derRepresentation)
        let login = ASImportableCredential.BasicAuthentication(
            userName: ASImportableEditableField(id: nil, fieldType: .string, value: "q@example.com"),
            password: ASImportableEditableField(id: nil, fieldType: .concealedString, value: "fictif-123"))
        let item = ASImportableItem(
            id: Data([0xAA]), created: created, lastModified: created, title: "WebAuthn.io",
            scope: ASImportableCredentialScope(urls: [URL(string: "https://webauthn.io")!]),
            credentials: [.passkey(passkey), .basicAuthentication(login)])
        let account = ASImportableAccount(
            id: Data([1]), userName: "", email: "", collections: [], items: [item])
        return ASExportedCredentialData(
            accounts: [account], formatVersion: .v1, exporterRelyingPartyIdentifier: "com.apple.Passwords",
            exporterDisplayName: "Mots de passe", timestamp: created)
    }

    @Test func encodesUnixSecondsTheCoreReads() throws {
        let json = try CredentialExchangeImport.cxfJSON(Self.exported())
        let root = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(root["timestamp"] as? Int == 1_700_000_000)
        #expect(CredentialExchangeImport.format == "cxf")
    }

    @Test func importedPasskeySignsForItsSite() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id

        let json = try CredentialExchangeImport.cxfJSON(Self.exported())
        let preview = try await VaultSession.previewImport(format: CredentialExchangeImport.format, data: json)
        #expect(preview.items == 1)
        #expect(preview.warnings.isEmpty)
        _ = try await session.importItems(format: CredentialExchangeImport.format, data: json, vaultID: vault)

        let row = try #require(session.summaries.first)
        #expect(row.passkeyCount == 1)
        #expect(session.counts().passkeys == 1)
        #expect(session.items(filter: .passkeys, query: "", sort: .title).map(\.id) == [row.id])

        let candidates = try await session.autofillCandidates(service: "webauthn.io", includeAll: false)
        let ref = try #require(candidates.first?.passkeys.first)
        #expect(ref.credentialId == Self.credentialID)
        let clientDataHash = Data(SHA256.hash(data: Data("client-data".utf8)))
        let assertion = try await session.passkeyAssertion(
            vaultID: vault, itemID: row.id, credentialID: Self.credentialID, clientDataHash: clientDataHash)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        #expect(Self.key.publicKey.isValidSignature(signature, for: assertion.authenticatorData + clientDataHash))
        #expect(assertion.userHandle == Data([9, 8, 7]))
    }
}
