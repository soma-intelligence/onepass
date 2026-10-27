import Foundation
import Testing

@testable import VaultKit

@Suite("Core labels")
struct CoreLabelsTests {
    /// The English folder of VaultKit's resource bundle (`Bundle.module` is VaultKit's, via @testable).
    private static let english: Bundle? = Bundle.module.path(forResource: "en", ofType: "lproj").flatMap(Bundle.init(path:))

    @Test func everyTemplateLabelHasAnEnglishEntry() throws {
        let en = try #require(Self.english)
        for info in itemTypes() {
            let type = CoreLabels.key(info.itemType)
            #expect(en.localizedString(forKey: "type.\(type)", value: nil, table: "CoreLabels") != "type.\(type)")
            for section in template(itemType: info.itemType) {
                let sectionKey = "section.\(type).\(section.id)"
                #expect(en.localizedString(forKey: sectionKey, value: nil, table: "CoreLabels") != sectionKey)
                for field in section.fields {
                    let key = "field.\(type).\(field.id)"
                    #expect(en.localizedString(forKey: key, value: nil, table: "CoreLabels") != key, "\(key)")
                }
            }
        }
    }

    @Test func renamedOrCustomLabelsAreShownAsStored() throws {
        let section = try #require(template(itemType: .login).first)
        var field = try #require(section.fields.first { $0.id == "username" })
        field.label = "Mon identifiant"
        #expect(field.displayLabel(itemType: .login) == "Mon identifiant")
        #expect(field.displayLabel == "Mon identifiant")
        let custom = FfiField(
            id: "custom_1", label: "Code du portail", kind: .text, value: .empty,
            required: false, repeatable: false, autofill: false)
        #expect(custom.displayLabel == "Code du portail")
        #expect(CoreLabels.menuOption("PostgreSQL") == "PostgreSQL")
        #expect(CoreLabels.menuOption("") == "")
    }
}
