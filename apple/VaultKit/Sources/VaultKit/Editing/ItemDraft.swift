import Foundation

/// The editing model of an item (spec 6.4), kept free of SwiftUI so it is tested by `swift test`.
///
/// Template fields stay in place: only repeated copies of a repeatable field and custom fields
/// (section `custom`, "Champs perso") can be removed. A cleared text value goes back to `.empty`,
/// so typing then erasing leaves the draft clean. Validation is the core's `validateItem`.
public struct ItemDraft: Equatable, Sendable {
    public var item: FfiItem
    /// The item as it was when editing started.
    public let original: FfiItem

    public static let customSectionID = "custom"
    public static let customSectionLabel = "Champs perso"
    static let customPrefix = "custom_"

    public init(item: FfiItem) {
        self.item = item
        original = item
    }

    public var isDirty: Bool { item != original }

    /// The first problem the core finds (empty title, missing required field, bad card number...).
    /// `field` is a field id or `title`; `reason` is the core's English reason (see
    /// `VaultError.validationMessage`). Never carries a value.
    public var validationError: (field: String, reason: String)? {
        guard case .Validation(let field, let reason)? = validateItem(item: preparedForSave()) else { return nil }
        return (field, reason)
    }

    // MARK: - Fields

    private func sectionIndex(_ sectionID: String) -> Int? {
        item.sections.firstIndex { $0.id == sectionID }
    }

    /// Sets a field value. Text-like values that are blank become `.empty`.
    public mutating func setValue(_ value: FfiFieldValue, sectionID: String, fieldIndex: Int) {
        guard let s = sectionIndex(sectionID), item.sections[s].fields.indices.contains(fieldIndex) else { return }
        item.sections[s].fields[fieldIndex].value = value.normalized
    }

    /// Adds an empty copy of a repeatable field right after its last occurrence in the section.
    public mutating func addRepeat(of fieldID: String, in sectionID: String) {
        guard let s = sectionIndex(sectionID),
            let last = item.sections[s].fields.lastIndex(where: { $0.id == fieldID })
        else { return }
        var copy = item.sections[s].fields[last]
        guard copy.repeatable else { return }
        copy.value = .empty
        copy.required = false
        item.sections[s].fields.insert(copy, at: last + 1)
    }

    /// True for a custom field and for a repeated copy (not the first occurrence of its id).
    public func isRemovable(sectionID: String, fieldIndex: Int) -> Bool {
        guard let s = sectionIndex(sectionID), item.sections[s].fields.indices.contains(fieldIndex) else {
            return false
        }
        if sectionID == Self.customSectionID { return true }
        let id = item.sections[s].fields[fieldIndex].id
        return item.sections[s].fields[..<fieldIndex].contains { $0.id == id }
    }

    /// True on the last occurrence of a repeatable field: where "+ ajouter" is offered.
    public func canRepeat(sectionID: String, fieldIndex: Int) -> Bool {
        guard let s = sectionIndex(sectionID), item.sections[s].fields.indices.contains(fieldIndex) else {
            return false
        }
        let field = item.sections[s].fields[fieldIndex]
        return field.repeatable && item.sections[s].fields.lastIndex { $0.id == field.id } == fieldIndex
    }

    /// Removes an added field; a template field is left alone.
    public mutating func removeField(sectionID: String, fieldIndex: Int) {
        guard isRemovable(sectionID: sectionID, fieldIndex: fieldIndex), let s = sectionIndex(sectionID) else { return }
        item.sections[s].fields.remove(at: fieldIndex)
    }

    /// Appends a field to the `custom` section ("Champs perso"), created when missing.
    /// Ids are `custom_<n>`, never reused within the item.
    public mutating func addCustomField(kind: FfiFieldType, label: String) {
        let s: Int
        if let existing = sectionIndex(Self.customSectionID) {
            s = existing
        } else {
            item.sections.append(FfiSection(id: Self.customSectionID, label: Self.customSectionLabel, fields: []))
            s = item.sections.count - 1
        }
        let used = item.sections.flatMap(\.fields).compactMap { field -> Int? in
            guard field.id.hasPrefix(Self.customPrefix) else { return nil }
            return Int(field.id.dropFirst(Self.customPrefix.count))
        }
        let next = max(used.max() ?? 0, Self.highestCustomNumber(in: original)) + 1
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        item.sections[s].fields.append(FfiField(
            id: Self.customPrefix + String(next), label: trimmed.isEmpty ? Self.defaultLabel(kind) : trimmed,
            kind: kind, value: .empty, required: false, repeatable: false, autofill: false))
    }

    private static func highestCustomNumber(in item: FfiItem) -> Int {
        item.sections.flatMap(\.fields).compactMap { field -> Int? in
            guard field.id.hasPrefix(customPrefix) else { return nil }
            return Int(field.id.dropFirst(customPrefix.count))
        }.max() ?? 0
    }

    /// Label used when the user leaves it blank, in the app's language (it is stored as typed).
    public static func defaultLabel(_ kind: FfiFieldType) -> String {
        switch kind {
        case .concealed: String(localized: "Champ masqué", bundle: VaultKitStrings.bundle)
        case .password: String(localized: "Mot de passe", bundle: VaultKitStrings.bundle)
        case .date: String(localized: "Date", bundle: VaultKitStrings.bundle)
        case .url: String(localized: "Site web", bundle: VaultKitStrings.bundle)
        case .email: String(localized: "Email", bundle: VaultKitStrings.bundle)
        case .phone: String(localized: "Téléphone", bundle: VaultKitStrings.bundle)
        case .location: String(localized: "Lieu", bundle: VaultKitStrings.bundle)
        default: String(localized: "Texte", bundle: VaultKitStrings.bundle)
        }
    }

    // MARK: - URLs and tags

    public mutating func addURL() {
        item.urls.append(FfiUrl(label: "", url: "", rule: .domain, primary: item.urls.isEmpty))
    }

    public mutating func removeURL(at index: Int) {
        guard item.urls.indices.contains(index) else { return }
        let wasPrimary = item.urls[index].primary
        item.urls.remove(at: index)
        if wasPrimary, !item.urls.isEmpty { item.urls[0].primary = true }
    }

    public mutating func setPrimaryURL(at index: Int) {
        guard item.urls.indices.contains(index) else { return }
        for i in item.urls.indices { item.urls[i].primary = i == index }
    }

    /// Adds a tag (trimmed), ignoring blanks and case-insensitive duplicates.
    public mutating func addTag(_ tag: String) {
        let trimmed = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !item.tags.contains(where: { $0.caseInsensitiveCompare(trimmed) == .orderedSame })
        else { return }
        item.tags.append(trimmed)
    }

    public mutating func removeTag(_ tag: String) {
        item.tags.removeAll { $0 == tag }
    }

    /// The item to hand to `VaultSession.save`: blank URLs dropped, URLs trimmed, one primary URL,
    /// custom fields left without a label get their default one back.
    public func preparedForSave() -> FfiItem {
        var out = item
        if let s = out.sections.firstIndex(where: { $0.id == Self.customSectionID }) {
            for f in out.sections[s].fields.indices {
                let label = out.sections[s].fields[f].label.trimmingCharacters(in: .whitespacesAndNewlines)
                out.sections[s].fields[f].label = label.isEmpty ? Self.defaultLabel(out.sections[s].fields[f].kind) : label
            }
        }
        out.urls = out.urls.compactMap { url in
            var url = url
            url.url = url.url.trimmingCharacters(in: .whitespacesAndNewlines)
            url.label = url.label.trimmingCharacters(in: .whitespacesAndNewlines)
            return url.url.isEmpty ? nil : url
        }
        if !out.urls.isEmpty, !out.urls.contains(where: \.primary) { out.urls[0].primary = true }
        if out.urls.filter(\.primary).count > 1, let first = out.urls.firstIndex(where: \.primary) {
            for i in out.urls.indices { out.urls[i].primary = i == first }
        }
        return out
    }
}

extension FfiFieldType {
    /// Masked until revealed (spec: password, concealed, OTP, recovery phrase).
    public var isSecret: Bool {
        switch self {
        case .password, .concealed, .otp, .mnemonic: true
        default: false
        }
    }
}

extension FfiFieldValue {
    /// The text of a text-like value, "" for anything else.
    public var text: String {
        switch self {
        case .text(let v), .concealed(let v), .password(let v), .url(let v), .email(let v), .phone(let v),
            .menu(let v), .otp(let v), .mnemonic(let v):
            v
        default:
            ""
        }
    }

    /// A text-like value of this field kind; "" gives `.empty`. Non-text kinds get `.text`.
    public static func fromText(_ s: String, kind: FfiFieldType) -> FfiFieldValue {
        if s.isEmpty { return .empty }
        return switch kind {
        case .concealed: .concealed(value: s)
        case .password: .password(value: s)
        case .url: .url(value: s)
        case .email: .email(value: s)
        case .phone: .phone(value: s)
        case .menu: .menu(value: s)
        case .otp: .otp(value: s)
        case .mnemonic: .mnemonic(value: s)
        default: .text(value: s)
        }
    }

    /// Empty text-like values collapse to `.empty`.
    var normalized: FfiFieldValue {
        switch self {
        case .text, .concealed, .password, .url, .email, .phone, .menu, .otp, .mnemonic:
            text.isEmpty ? .empty : self
        default:
            self
        }
    }

    /// Nothing to show in the detail view.
    public var isBlank: Bool {
        switch self {
        case .empty: true
        case .text, .concealed, .password, .url, .email, .phone, .menu, .otp, .mnemonic:
            text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .barcode(let value, _): value.isEmpty
        case .address(let a):
            [a.line1, a.line2, a.city, a.postalCode, a.region, a.country].allSatisfy(\.isEmpty)
        case .itemLink(let id): id.isEmpty
        default: false
        }
    }
}
