import Foundation
import Testing

@testable import VaultKit

/// A fresh item of this type built from the core template, without a session.
func draftItem(_ type: FfiItemType, title: String = "Projet Atlas") -> FfiItem {
    FfiItem(
        id: "00112233445566778899aabbccddeeff", vaultId: "ffeeddccbbaa99887766554433221100",
        itemType: type, title: title, tags: [], favorite: false, color: nil, notes: "", urls: [],
        apps: [], locations: [], loginMethods: [], sections: template(itemType: type), expires: nil,
        rotateEveryDays: nil, reprompt: false, hideFromAutofill: false, watchtowerExclusions: [],
        onWatch: false, archived: false, trashedAt: nil, createdAt: 1_790_000_000,
        updatedAt: 1_790_000_000, passwordHistoryCount: 0, attachmentCount: 0)
}

private func index(_ draft: ItemDraft, _ fieldID: String, section: String = "main") -> Int {
    draft.item.sections.first { $0.id == section }!.fields.firstIndex { $0.id == fieldID }!
}

private func ids(_ draft: ItemDraft, section: String = "main") -> [String] {
    draft.item.sections.first { $0.id == section }!.fields.map(\.id)
}

@Suite("Item editor model")
struct ItemEditorModelTests {
    @Test func setValueMarksDirty() {
        var draft = ItemDraft(item: draftItem(.login))
        #expect(!draft.isDirty)
        let username = index(draft, "username")
        draft.setValue(.text(value: "camille.durand@exemple.fr"), sectionID: "main", fieldIndex: username)
        #expect(draft.isDirty)
        #expect(draft.item.sections[0].fields[username].value == .text(value: "camille.durand@exemple.fr"))

        // Clearing the text puts the field back to empty: nothing left to save.
        draft.setValue(.text(value: ""), sectionID: "main", fieldIndex: username)
        #expect(draft.item.sections[0].fields[username].value == .empty)
        #expect(!draft.isDirty)

        draft.item.title = "Autre titre"
        #expect(draft.isDirty)
    }

    @Test func addRepeatInsertsAfterLastSameID() {
        var draft = ItemDraft(item: draftItem(.login))
        let before = ids(draft)
        draft.addRepeat(of: "security_question", in: "main")
        draft.addRepeat(of: "security_question", in: "main")
        var expected = before
        let at = expected.firstIndex(of: "security_question")!
        expected.insert(contentsOf: ["security_question", "security_question"], at: at + 1)
        #expect(ids(draft) == expected)

        let copies = draft.item.sections[0].fields.filter { $0.id == "security_question" }
        #expect(copies.count == 3)
        #expect(copies.allSatisfy { $0.label == "Question de sécurité" && $0.kind == .text && $0.repeatable })
        #expect(copies.dropFirst().allSatisfy { $0.value == .empty && !$0.required })
        #expect(draft.isDirty)

        // Only repeatable fields can be repeated, and only existing ones.
        let snapshot = draft
        draft.addRepeat(of: "username", in: "main")
        draft.addRepeat(of: "nope", in: "main")
        draft.addRepeat(of: "security_question", in: "nope")
        #expect(draft == snapshot)
    }

    @Test func customFieldGoesToCustomSection() {
        var draft = ItemDraft(item: draftItem(.login))
        #expect(!draft.item.sections.contains { $0.id == ItemDraft.customSectionID })
        draft.addCustomField(kind: .concealed, label: "Code d'entrée")
        draft.addCustomField(kind: .date, label: "Échéance")

        let custom = draft.item.sections.last!
        #expect(custom.id == "custom")
        #expect(custom.label == "Champs perso")
        #expect(custom.fields.map(\.id) == ["custom_1", "custom_2"])
        #expect(custom.fields.map(\.label) == ["Code d'entrée", "Échéance"])
        #expect(custom.fields.map(\.kind) == [.concealed, .date])
        #expect(custom.fields.allSatisfy { $0.value == .empty && !$0.required && !$0.repeatable })
        #expect(draft.item.sections.filter { $0.id == "custom" }.count == 1)

        // Numbering continues after a removal: ids are never reused.
        draft.removeField(sectionID: "custom", fieldIndex: 0)
        draft.addCustomField(kind: .url, label: "Intranet")
        #expect(ids(draft, section: "custom") == ["custom_2", "custom_3"])
    }

    @Test func validationSurfacesRequiredField() {
        var draft = ItemDraft(item: draftItem(.login))
        let error = draft.validationError
        #expect(error?.field == "username")
        #expect(error?.reason == "is required")

        draft.setValue(.text(value: "camille.durand"), sectionID: "main", fieldIndex: index(draft, "username"))
        #expect(draft.validationError == nil)

        draft.item.title = "   "
        #expect(draft.validationError?.field == "title")
    }

    @Test func removeOnlyAddedFields() {
        var draft = ItemDraft(item: draftItem(.login))
        let template = draft
        let username = index(draft, "username")
        #expect(!draft.isRemovable(sectionID: "main", fieldIndex: username))
        draft.removeField(sectionID: "main", fieldIndex: username)
        #expect(draft == template)

        // The first occurrence of a repeatable field belongs to the template too.
        let question = index(draft, "security_question")
        draft.removeField(sectionID: "main", fieldIndex: question)
        #expect(draft == template)

        // A repeated copy and a custom field can go.
        draft.addRepeat(of: "security_question", in: "main")
        #expect(draft.isRemovable(sectionID: "main", fieldIndex: question + 1))
        draft.removeField(sectionID: "main", fieldIndex: question + 1)
        #expect(draft == template)

        draft.addCustomField(kind: .text, label: "Numéro client")
        #expect(draft.isRemovable(sectionID: "custom", fieldIndex: 0))
        draft.removeField(sectionID: "custom", fieldIndex: 0)
        #expect(draft.item.sections.first { $0.id == "custom" }?.fields.isEmpty ?? true)

        // Out of range: nothing happens.
        let snapshot = draft
        draft.removeField(sectionID: "main", fieldIndex: 999)
        draft.removeField(sectionID: "nope", fieldIndex: 0)
        #expect(draft == snapshot)
    }

    @Test func preparedForSaveDropsBlankUrlsAndKeepsOnePrimary() {
        var draft = ItemDraft(item: draftItem(.login))
        draft.addURL()
        draft.addURL()
        draft.item.urls[1].url = " https://exemple.fr "
        draft.addTag("Travail")
        draft.addTag(" travail ")
        draft.addTag("Projet Atlas")
        #expect(draft.item.tags == ["Travail", "Projet Atlas"])

        let saved = draft.preparedForSave()
        #expect(saved.urls.map(\.url) == ["https://exemple.fr"])
        #expect(saved.urls.map(\.primary) == [true])

        draft.setPrimaryURL(at: 1)
        #expect(draft.item.urls.map(\.primary) == [false, true])
    }

    @Test func textValuesFollowTheFieldKind() {
        #expect(FfiFieldValue.fromText("abc", kind: .password) == .password(value: "abc"))
        #expect(FfiFieldValue.fromText("abc", kind: .otp) == .otp(value: "abc"))
        #expect(FfiFieldValue.fromText("abc", kind: .menu) == .menu(value: "abc"))
        #expect(FfiFieldValue.fromText("", kind: .email) == .empty)
        #expect(FfiFieldValue.password(value: "x").text == "x")
        #expect(FfiFieldValue.empty.text == "")
        #expect(FfiFieldType.mnemonic.isSecret && FfiFieldType.otp.isSecret && !FfiFieldType.url.isSecret)
    }
}

@Suite("Password strength")
struct PasswordStrengthTests {
    @Test func estimateGrowsWithLengthAndPool() {
        #expect(PasswordStrength.estimatedBits("") == 0)
        #expect(abs(PasswordStrength.estimatedBits("abcd") - 4 * log2(26.0)) < 0.001)
        #expect(PasswordStrength.estimatedBits("abcd1234") > PasswordStrength.estimatedBits("abcdefgh"))
        // A 20-character mixed password lights the whole meter.
        #expect(PasswordStrength.estimatedBits("tj7N-qe4L-wPz9-Kc2m!") >= 100)
    }
}

@Suite("Item editor model, fix round 1")
struct ItemEditorFixTests {
    /// Default labels are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func documentWithoutFileValidates() {
        // Attachments come in milestone 5: a required file field does not block the save.
        let draft = ItemDraft(item: draftItem(.document, title: "Attestation"))
        #expect(draft.validationError == nil)
        #expect(ItemDraft(item: draftItem(.document, title: " ")).validationError?.field == "title")
    }

    @Test func blankCustomLabelGetsItsDefaultBack() {
        var draft = ItemDraft(item: draftItem(.login))
        draft.addCustomField(kind: .phone, label: "Standard")
        let s = draft.item.sections.firstIndex { $0.id == "custom" }!
        draft.item.sections[s].fields[0].label = "   "
        let saved = draft.preparedForSave()
        #expect(saved.sections[s].fields[0].label == "Téléphone")
        draft.item.sections[s].fields[0].label = " Accueil "
        #expect(draft.preparedForSave().sections[s].fields[0].label == "Accueil")
    }

    @Test func numberInputAcceptsCommaDotAndMinus() {
        #expect(NumberInput.decimal("12,5") == Decimal(string: "12.5"))
        #expect(NumberInput.decimal("12.5") == Decimal(string: "12.5"))
        #expect(NumberInput.decimal("-0,75") == Decimal(string: "-0.75"))
        #expect(NumberInput.decimal("2\u{202F}500,00") == Decimal(2500))
        #expect(NumberInput.decimal("12,") == Decimal(12))
        #expect(NumberInput.decimal("1,2,3") == nil)
        #expect(NumberInput.decimal("abc") == nil)
        #expect(NumberInput.decimal("-") == nil)
        #expect(NumberInput.decimal("") == nil)
        #expect(NumberInput.integer("1 250") == 1250)
        #expect(NumberInput.integer("-42") == -42)
        #expect(NumberInput.integer("4,2") == nil)
        #expect(NumberInput.integer("99999999999999999999") == nil)
        #expect(NumberInput.double("-33,8688") == -33.8688)
        #expect(NumberInput.double("151.2093") == 151.2093)
        #expect(NumberInput.text(Decimal(string: "-12.5")!) == "-12,5")
        #expect(NumberInput.text(48.856610) == "48,85661")
        #expect(NumberInput.text(-2.0) == "-2")
    }
}

/// Bug 6: the generator sheet (recipe bits) and the field meter (estimate of the string) agree.
@Suite("Password strength agreement")
struct PasswordStrengthAgreementTests {
    static let recipes: [FfiPasswordRecipe] = [
        .words(count: 5, separator: "-", french: true, capitalize: false),
        .words(count: 3, separator: " ", french: false, capitalize: true),
        .words(count: 7, separator: ".", french: true, capitalize: false),
        .pin(length: 6),
        .characters(length: 20, digits: true, symbols: true, avoidAmbiguous: false),
        .characters(length: 16, digits: true, symbols: false, avoidAmbiguous: false),
        .characters(length: 12, digits: false, symbols: true, avoidAmbiguous: false),
    ]

    @Test(arguments: recipes)
    func generatedPasswordGetsItsRecipeBits(recipe: FfiPasswordRecipe) throws {
        for _ in 0..<10 {
            let generated = try generatePassword(recipe: recipe)
            let expected = passwordEntropyBits(recipe: recipe)
            #expect(abs(PasswordStrength.estimatedBits(generated) - expected) < 1e-9)
        }
    }

    @Test func fiveWordPassphraseIsNotExcellentOnceSaved() throws {
        let generated = try generatePassword(recipe: .words(count: 5, separator: "-", french: true, capitalize: false))
        let bits = PasswordStrength.estimatedBits(generated)
        #expect(abs(bits - 5 * log2(7776.0)) < 1e-9)
        #expect(bits < 80)
    }
}

/// The onboarding gate: five random list words pass, four do not; the meter labels stay shared.
@Suite("Master password gate")
struct MasterPasswordGateTests {
    @Test func fiveRandomWordsPassFourDoNot() throws {
        for _ in 0..<20 {
            let five = try generatePassword(recipe: PasswordStrength.masterPasswordRecipe)
            #expect(PasswordStrength.acceptsMasterPassword(five))
            let four = try generatePassword(recipe: .words(count: 4, separator: "-", french: true, capitalize: false))
            #expect(!PasswordStrength.acceptsMasterPassword(four))
            let english = try generatePassword(recipe: .words(count: 5, separator: " ", french: false, capitalize: false))
            #expect(PasswordStrength.acceptsMasterPassword(english))
        }
        // The tip's example is five words of the French list.
        #expect(abs(PasswordStrength.estimatedBits("tapis-orage-girafe-violon-nuage") - 5 * log2(7776.0)) < 1e-9)
        #expect(PasswordStrength.acceptsMasterPassword("tapis-orage-girafe-violon-nuage"))
    }

    @Test func generatorAndFieldStillAgree() throws {
        let recipe = PasswordStrength.masterPasswordRecipe
        let generated = try generatePassword(recipe: recipe)
        #expect(abs(PasswordStrength.estimatedBits(generated) - passwordEntropyBits(recipe: recipe)) < 1e-9)
    }
}
