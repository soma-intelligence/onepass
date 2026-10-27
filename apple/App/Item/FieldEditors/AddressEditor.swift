import SwiftUI
import VaultKit

/// Postal address: six text fields (ligne 1, ligne 2, ville, code postal, région, pays).
struct AddressEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private static let blank = FfiAddress(line1: "", line2: "", city: "", postalCode: "", region: "", country: "")

    private var address: FfiAddress {
        if case .address(let a) = value { a } else { Self.blank }
    }

    private func part(_ keyPath: WritableKeyPath<FfiAddress, String>) -> Binding<String> {
        Binding(
            get: { address[keyPath: keyPath] },
            set: { text in
                var a = address
                a[keyPath: keyPath] = text
                value = a == Self.blank ? .empty : .address(value: a)
            })
    }

    var body: some View {
        VStack(spacing: 8) {
            TextField("Ligne 1", text: part(\.line1))
                .addressContent(.line1)
                .accessibilityIdentifier("editor.field.\(field.id)")
            TextField("Ligne 2", text: part(\.line2))
                .addressContent(.line2)
            HStack {
                TextField("Code postal", text: part(\.postalCode))
                    .addressContent(.postalCode)
                    .frame(maxWidth: 120)
                TextField("Ville", text: part(\.city))
                    .addressContent(.city)
            }
            TextField("Région", text: part(\.region))
                .addressContent(.region)
            TextField("Pays", text: part(\.country))
                .addressContent(.country)
        }
    }

    /// One line per non-empty part, for the detail view and the copy.
    static func lines(_ a: FfiAddress) -> String {
        let cityLine = [a.postalCode, a.city].filter { !$0.isEmpty }.joined(separator: " ")
        return [a.line1, a.line2, cityLine, a.region, a.country].filter { !$0.isEmpty }.joined(separator: "\n")
    }
}

enum AddressPart { case line1, line2, city, postalCode, region, country }

extension View {
    /// AutoFill hint of each address line (iOS).
    func addressContent(_ part: AddressPart) -> some View {
        #if os(iOS) || os(visionOS)
        let type: UITextContentType =
            switch part {
            case .line1: .streetAddressLine1
            case .line2: .streetAddressLine2
            case .city: .addressCity
            case .postalCode: .postalCode
            case .region: .addressState
            case .country: .countryName
            }
        return textContentType(type)
        #else
        return self
        #endif
    }
}
