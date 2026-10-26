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
