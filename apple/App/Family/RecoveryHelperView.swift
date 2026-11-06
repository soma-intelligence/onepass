import SwiftUI
import VaultKit

/// The organizer's side (spec 11.4, 11.5): the member who chose this account, "Demander la
/// récupération" after a loss (master password), the delay on this clock, then the face-to-face
/// handover once it is over.
struct RecoveryHelperView: View {
    @Environment(AppModel.self) private var model
    let helper: FfiHelper
    @State private var status: FfiRecoveryStatus?
    @State private var password = ""
    @State private var errorMessage: String?
    @StateObject private var holder = ReleaseHolder()

    var body: some View {
        Form {
            Section { Text(VaultSession.helperMessage(helper)) }
            switch status {
            case .waiting(let after)?:
                Section {
                    let date = Date(timeIntervalSince1970: TimeInterval(after))
                    Text("recovery.helper.waiting \(date.formatted(date: .long, time: .shortened))")
                }
            case .ready?:
                releaseSection
            case .cancelled?:
                Section { Text("recovery.helper.cancelled").foregroundStyle(.secondary) }
            default:
                Section {
                    SecureField("recovery.enroll.password", text: $password)
                    Button("recovery.helper.request") { request() }
                        .disabled(password.isEmpty)
                        .accessibilityIdentifier("recovery.helper.request")
                } footer: {
                    Text("recovery.helper.requestFooter")
                }
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("recovery.section")
        .task { status = try? await model.session.recoveryStatus(of: helper.member) }
    }

    @ViewBuilder private var releaseSection: some View {
        Section {
            if let flow = holder.flow {
                ReleaseStateView(flow: flow)
            } else {
                #if os(iOS)
                Button("sharing.verify.scanCode") { holder.scanning = true }
                    .accessibilityIdentifier("recovery.helper.scan")
                #endif
            }
        } footer: {
            Text("recovery.helper.releaseFooter")
        }
        #if os(iOS)
        .sheet(isPresented: $holder.scanning) {
            SecretKeyScanner(onKey: { text in
                holder.scanning = false
                let flow = model.session.recoveryReleaseFlow(member: helper.member)
                holder.flow = flow
                flow?.scan(qrText: text)
            }, accept: { $0 })
        }
        #endif
    }

    private func request() {
        let secret = SecretBytes(utf8: password)
        password = ""
        Task {
            defer { secret.wipe() }
            do {
                status = try await model.session.requestRecovery(of: helper.member, password: secret)
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }

    @MainActor final class ReleaseHolder: ObservableObject {
        @Published var flow: RecoveryReleaseFlow?
        @Published var scanning = false
    }
}

private struct ReleaseStateView: View {
    @ObservedObject var flow: RecoveryReleaseFlow

    var body: some View {
        switch flow.state {
        case .idle, .scanning, .releasing:
            ProgressView().frame(maxWidth: .infinity)
        case .comparing(let sas):
            Text(sas).font(.system(size: 34, weight: .bold, design: .monospaced)).frame(maxWidth: .infinity)
            Button("sharing.verify.same") { flow.confirm() }
            Button("sharing.verify.different", role: .destructive) { flow.reject() }
        case .done:
            Label("recovery.helper.released", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
        case .failed(let failure):
            Label(failure.message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
        }
    }
}
