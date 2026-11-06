import SwiftUI
import VaultKit

/// A member's keys changed (spec 12.3, decision 6, ruling C-2): a reader is confirmed with the
/// 6-digit code shown on their iPhone, a writer or a manager in person only.
struct IdentityChangeView: View {
    @Environment(AppModel.self) private var model
    @State private var codes: [String: String] = [:]
    @State private var errorMessage: String?
    @State private var verifying = false

    var body: some View {
        Form {
            ForEach(model.session.sharing.identityChanges, id: \.child) { change in
                section(change)
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("sharing.identity.title")
        .sheet(isPresented: $verifying) { VerifyContactView() }
    }

    @ViewBuilder private func section(_ change: FfiIdentityChange) -> some View {
        let offer = model.session.identityChangeOffer(for: change)
        Section {
            Text(offer.message)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("sharing.identity.message")
            switch offer {
            case .code:
                TextField("sharing.identity.code", text: Binding(
                    get: { codes[change.child] ?? "" }, set: { codes[change.child] = $0 }))
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    #endif
                    .accessibilityIdentifier("sharing.identity.codeField")
                Button("sharing.identity.confirm") { adopt(change) }
                    .disabled(UInt32(codes[change.child] ?? "") == nil)
                    .accessibilityIdentifier("sharing.identity.confirm")
            case .inPerson, .forked:
                Button("sharing.verify.inPerson") { verifying = true }
                    .accessibilityIdentifier("sharing.identity.inPerson")
            }
        }
    }

    private func adopt(_ change: FfiIdentityChange) {
        guard let code = UInt32(codes[change.child] ?? "") else { return }
        errorMessage = nil
        Task {
            do {
                try await model.session.adoptMemberIdentity(change, proof: .code(code: code))
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
