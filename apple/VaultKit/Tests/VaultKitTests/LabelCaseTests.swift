import Testing

@testable import VaultKit

/// Field and section labels: French keeps the house lowercase ("mot de passe"); English, Spanish and
/// Italian keep their own capitalization, so an English label never reads like a raw field id.
@Suite("Label case")
struct LabelCaseTests {
    @Test func frenchLowersTheFirstLetter() {
        #expect(LabelCase.detail("Mot de passe", language: "fr") == "mot de passe")
        #expect(LabelCase.detail("Identifiant", language: "fr-CA") == "identifiant")
    }

    @Test func acronymsStayInEveryLanguage() {
        #expect(LabelCase.detail("PIN", language: "fr") == "PIN")
        #expect(LabelCase.detail("URL de base", language: "fr") == "URL de base")
    }

    @Test func otherLanguagesStartWithACapital() {
        #expect(LabelCase.detail("Username", language: "en") == "Username")
        #expect(LabelCase.detail("Passkeys", language: "en-US") == "Passkeys")
        #expect(LabelCase.detail("website", language: "en") == "Website")
        #expect(LabelCase.detail("añadir a", language: "es") == "Añadir a")
        #expect(LabelCase.detail("Nome utente", language: "it") == "Nome utente")
    }
}
