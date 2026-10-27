import Foundation

/// Display text for the French text the core puts in items: item type names, template section and
/// field labels, menu options. Stored data never changes (the core keeps its French labels and
/// menu values); only what the apps show is localized, from VaultKit's `CoreLabels` table
/// (generated from the core's templates.rs and menus.rs).
///
/// A label is translated only while it is still the template's own: a field the user renamed, or
/// a custom field, shows its stored label as is.
public enum CoreLabels {
    private static let table = "CoreLabels"

    /// Singular name of an item type (the core's `itemTypes()` label, localized).
    public static func typeName(_ type: FfiItemType) -> String {
        let fallback = itemTypes().first { $0.itemType == type }?.label ?? ""
        return lookup("type.\(key(type))", fallback: fallback)
    }

    /// Display label of a template field. `itemType` narrows the lookup; without it the field is
    /// found by its id and stored label (unambiguous across the 26 templates).
    public static func fieldLabel(_ field: FfiField, itemType: FfiItemType? = nil) -> String {
        guard let type = itemType.map(key) ?? templates.fieldOwner[pair(field.id, field.label)],
              templates.fields["\(type).\(field.id)"] == field.label
        else { return field.label }
        return lookup("field.\(type).\(field.id)", fallback: field.label)
    }

    /// Display label of a section: template sections, the importer's `imported` section and the
    /// editor's `custom` section.
    public static func sectionLabel(_ section: FfiSection, itemType: FfiItemType? = nil) -> String {
        if section.id == importedSectionID, section.label == importedSectionLabel {
            return lookup("section.imported", fallback: section.label)
        }
        if section.id == ItemDraft.customSectionID, section.label == ItemDraft.customSectionLabel {
            return lookup("section.custom", fallback: section.label)
        }
        guard let type = itemType.map(key) ?? templates.sectionOwner[pair(section.id, section.label)],
              templates.sections["\(type).\(section.id)"] == section.label
        else { return section.label }
        return lookup("section.\(type).\(section.id)", fallback: section.label)
    }

    /// Display text of a menu value (`menuOptions` entries such as "Mensuel" or "oui"). Values the
    /// table does not know (product names, user text) come back unchanged.
    public static func menuOption(_ value: String) -> String {
        value.isEmpty ? value : lookup("menu.\(value)", fallback: value)
    }

    /// The section and its label the core's importer adds (import/build.rs).
    static let importedSectionID = "imported"
    static let importedSectionLabel = "Importé"

    // MARK: - Lookup

    private static func lookup(_ key: String, fallback: String) -> String {
        VaultKitStrings.bundle.localizedString(forKey: key, value: fallback, table: table)
    }

    private static func pair(_ id: String, _ label: String) -> String { id + "\u{1F}" + label }

    /// The core's template text, read once: "<type>.<id>" to French label, and (id, label) to the
    /// type that owns it.
    private struct Templates: Sendable {
        var fields: [String: String] = [:]
        var sections: [String: String] = [:]
        var fieldOwner: [String: String] = [:]
        var sectionOwner: [String: String] = [:]
    }

    private static let templates: Templates = {
        var t = Templates()
        for info in itemTypes() {
            let type = key(info.itemType)
            for section in template(itemType: info.itemType) {
                t.sections["\(type).\(section.id)"] = section.label
                if t.sectionOwner[pair(section.id, section.label)] == nil {
                    t.sectionOwner[pair(section.id, section.label)] = type
                }
                for field in section.fields {
                    t.fields["\(type).\(field.id)"] = field.label
                    if t.fieldOwner[pair(field.id, field.label)] == nil {
                        t.fieldOwner[pair(field.id, field.label)] = type
                    }
                }
            }
        }
        return t
    }()

    /// Key of a type in the table: the Swift case name.
    static func key(_ type: FfiItemType) -> String {
        switch type {
        case .login: "login"
        case .secureNote: "secureNote"
        case .password: "password"
        case .email: "email"
        case .server: "server"
        case .database: "database"
        case .router: "router"
        case .apiCredential: "apiCredential"
        case .sshKey: "sshKey"
        case .creditCard: "creditCard"
        case .bankAccount: "bankAccount"
        case .cryptoWallet: "cryptoWallet"
        case .subscription: "subscription"
        case .identity: "identity"
        case .idCard: "idCard"
        case .passport: "passport"
        case .driverLicense: "driverLicense"
        case .socialSecurityNumber: "socialSecurityNumber"
        case .medicalRecord: "medicalRecord"
        case .membership: "membership"
        case .rewardProgram: "rewardProgram"
        case .insurance: "insurance"
        case .vehicle: "vehicle"
        case .accessCode: "accessCode"
        case .document: "document"
        case .softwareLicense: "softwareLicense"
        }
    }
}

extension FfiField {
    /// The label to show for this field (see `CoreLabels.fieldLabel`). Never write it back.
    public var displayLabel: String { CoreLabels.fieldLabel(self) }

    /// The label to show for this field of an item of type `itemType`.
    public func displayLabel(itemType: FfiItemType) -> String { CoreLabels.fieldLabel(self, itemType: itemType) }
}

extension FfiSection {
    /// The label to show for this section (see `CoreLabels.sectionLabel`). Never write it back.
    public var displayLabel: String { CoreLabels.sectionLabel(self) }

    /// The label to show for this section of an item of type `itemType`.
    public func displayLabel(itemType: FfiItemType) -> String { CoreLabels.sectionLabel(self, itemType: itemType) }
}
