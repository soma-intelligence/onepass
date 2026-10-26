import DesignKit
import SwiftUI
import VaultKit

/// The 26 item types grouped as in the architecture spec 5.4 (Accès, Finance, Identité, Biens et
/// contrats, Autres). Menu content: works inside a `Menu` (toolbar "Nouvel élément") and inside a
/// `List` (the ⌘N sheet, the iPhone sheet).
struct NewItemMenu: View {
    private let onPick: (FfiItemType) -> Void

    init(onPick: @escaping (FfiItemType) -> Void) {
        self.onPick = onPick
    }

    struct TypeGroup: Identifiable, Sendable {
        let title: LocalizedStringResource
        let types: [FfiItemType]
        var id: String { String(localized: title) }
    }

    static let groups: [TypeGroup] = [
        TypeGroup(title: "Accès", types: [.login, .password, .email, .server, .database, .router, .apiCredential, .sshKey]),
        TypeGroup(title: "Finance", types: [.creditCard, .bankAccount, .cryptoWallet, .subscription]),
        TypeGroup(title: "Identité", types: [
            .identity, .idCard, .passport, .driverLicense, .socialSecurityNumber, .medicalRecord, .membership,
            .rewardProgram,
        ]),
        TypeGroup(title: "Biens et contrats", types: [.insurance, .vehicle, .accessCode]),
        TypeGroup(title: "Autres", types: [.secureNote, .document, .softwareLicense]),
    ]

    /// Stable name of a type for accessibility identifiers: `newItem.login`, `newItem.creditCard`.
    static func key(_ type: FfiItemType) -> String { String(describing: type) }

    var body: some View {
        ForEach(Self.groups) { group in
            Section {
                ForEach(group.types, id: \.self) { type in
                    let category = ItemCategory.of(type)
                    Button {
                        onPick(type)
                    } label: {
                        Label(category.singular, systemImage: category.symbol)
                    }
                    .accessibilityIdentifier("newItem.\(Self.key(type))")
                }
            } header: {
                Text(group.title)
            }
        }
    }
}

/// ⌘N: the type picker in a sheet, then the new item's editor in the detail.
struct NewItemSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                NewItemMenu { type in
                    dismiss()
                    model.perform(.newItem(type))
                }
            }
            .navigationTitle("Nouvel élément")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 340, minHeight: 520)
        #endif
    }
}
