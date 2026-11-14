import Foundation

/// The editing model of an item (spec 6.4), kept free of SwiftUI so it is tested by `swift test`.
///
/// Template fields stay in place: only repeated copies of a repeatable field and the fields of a
/// free section (any section the type's template does not have: `custom`, an importer's
/// `imported`, `section_<n>` added in the editor) can be removed. A cleared text value goes back to `.empty`,
/// so typing then erasing leaves the draft clean. Validation is the core's `validateItem`.
public struct ItemDraft: Equatable, Sendable {
    public var item: FfiItem
    /// The item as it was when editing started.
    public let original: FfiItem

    public static let customSectionID = "custom"
    public static let customSectionLabel = "Champs perso"
    static let customPrefix = "custom_"
    public static let sectionPrefix = "section_"

    /// Label of a new free section, and of one left without a name at save.
    public static func defaultSectionLabel() -> String {
        String(localized: "editing.newSection", bundle: VaultKitStrings.bundle)
    }

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

    /// True for a field of a free section and for a repeated copy (not the first occurrence of its id).
    public func isRemovable(sectionID: String, fieldIndex: Int) -> Bool {
        guard let s = sectionIndex(sectionID), item.sections[s].fields.indices.contains(fieldIndex) else {
            return false
        }
        if isFreeSection(sectionID) { return true }
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

    /// Appends a field to a free section, or to the `custom` section ("Champs perso", created when
    /// missing) when `sectionID` is nil. A template section is refused. Ids are `custom_<n>`, never
    /// reused within the item.
    public mutating func addCustomField(kind: FfiFieldType, label: String, sectionID: String? = nil) {
        let s: Int
        if let sectionID {
            guard isFreeSection(sectionID), let existing = sectionIndex(sectionID) else { return }
            s = existing
        } else if let existing = sectionIndex(Self.customSectionID) {
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
        case .concealed: String(localized: "editing.hiddenField", bundle: VaultKitStrings.bundle)
        case .password: String(localized: "Mot de passe", bundle: VaultKitStrings.bundle)
        case .date: String(localized: "editing.date", bundle: VaultKitStrings.bundle)
        case .url: String(localized: "editing.website", bundle: VaultKitStrings.bundle)
        case .email: String(localized: "editing.email", bundle: VaultKitStrings.bundle)
        case .phone: String(localized: "editing.phone", bundle: VaultKitStrings.bundle)
        case .location: String(localized: "editing.place", bundle: VaultKitStrings.bundle)
        default: String(localized: "editing.text", bundle: VaultKitStrings.bundle)
        }
    }

    // MARK: - Free sections

    private var templateSectionIDs: Set<String> { Set(template(itemType: item.itemType).map(\.id)) }

    /// A section the type's template does not have: renamable, movable and removable.
    public func isFreeSection(_ sectionID: String) -> Bool { !templateSectionIDs.contains(sectionID) }

    /// The free sections, in the item's order.
    public var freeSectionIDs: [String] { item.sections.map(\.id).filter(isFreeSection) }

    /// Moves a free section among the free ones (indices into `freeSectionIDs`, the target
    /// clamped). Template sections stay first, in their order.
    public mutating func moveFreeSection(from: Int, to: Int) {
        let templates = Set(templateSectionIDs)
        var free = item.sections.filter { !templates.contains($0.id) }
        guard free.indices.contains(from) else { return }
        let moving = free.remove(at: from)
        free.insert(moving, at: min(max(to, 0), free.count))
        item.sections = item.sections.filter { templates.contains($0.id) } + free
    }

    /// Moves a field within a free section; a template section is left alone.
    public mutating func moveField(sectionID: String, from: Int, to: Int) {
        guard isFreeSection(sectionID), let s = sectionIndex(sectionID),
            item.sections[s].fields.indices.contains(from)
        else { return }
        let field = item.sections[s].fields.remove(at: from)
        item.sections[s].fields.insert(field, at: min(max(to, 0), item.sections[s].fields.count))
    }

    /// Appends an empty free section and returns its id, `section_<n>`, never reused within the item.
    /// A blank label stays blank while editing (the name field prompts the default); the save fills it.
    @discardableResult
    public mutating func addSection(label: String? = nil) -> String {
        let next = max(Self.highestSectionNumber(in: item), Self.highestSectionNumber(in: original)) + 1
        let id = Self.sectionPrefix + String(next)
        let trimmed = label?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        item.sections.append(FfiSection(id: id, label: trimmed, fields: []))
        return id
    }

    private static func highestSectionNumber(in item: FfiItem) -> Int {
        item.sections.compactMap { section -> Int? in
            guard section.id.hasPrefix(sectionPrefix) else { return nil }
            return Int(section.id.dropFirst(sectionPrefix.count))
        }.max() ?? 0
    }

    public mutating func renameSection(id: String, label: String) {
        guard isFreeSection(id), let s = sectionIndex(id) else { return }
        item.sections[s].label = label
    }

    public mutating func removeSection(id: String) {
        guard isFreeSection(id) else { return }
        item.sections.removeAll { $0.id == id }
    }

    // MARK: - Sign-in provider

    /// Drops the "sign in with" provider; the username stays as typed and is required again.
    public mutating func clearSignInProvider() {
        item.loginMethods.removeAll {
            if case .provider = $0 { return true }
            return false
        }
    }

    // MARK: - URLs and tags

    /// Reorders the websites; the primary flag stays on its website. The target is clamped.
    public mutating func moveURL(from: Int, to: Int) {
        guard item.urls.indices.contains(from) else { return }
        let url = item.urls.remove(at: from)
        item.urls.insert(url, at: min(max(to, 0), item.urls.count))
    }

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
    /// free sections left without a field dropped, free sections and their fields left without a
    /// label get their default one back.
    public func preparedForSave() -> FfiItem {
        var out = item
        out.sections.removeAll { isFreeSection($0.id) && $0.fields.isEmpty }
        for s in out.sections.indices where isFreeSection(out.sections[s].id) {
            let name = out.sections[s].label.trimmingCharacters(in: .whitespacesAndNewlines)
            out.sections[s].label = name.isEmpty ? Self.defaultSectionLabel() : name
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
