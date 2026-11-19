import DesignKit
import SwiftUI
import VaultKit

/// The one-time password row of the editor: the masked secret with its eye and the QR scan (camera
/// on the iPhone, an image on the Mac). No live code here: the item's page shows it.
struct OtpRow: View {
    let field: FfiField
    let label: String
    var message: String?
    @Binding var value: FfiFieldValue

    var body: some View {
        EditorRow(label: label, message: message) {
            SecretFieldEditor(field: field, value: $value, showsLiveCode: false)
        }
    }
}
