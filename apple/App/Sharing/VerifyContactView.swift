import SwiftUI
import VaultKit

/// "Vérifier en personne" (spec 5.3.1) or "Inviter par lien" (spec 5.3.2). In person: one shows
/// the QR, the other scans it, both compare the code; by link: the system share sheet carries the
/// link, the contact arrives at the Link level ("Non vérifié").
struct VerifyContactView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var byLink = false

    var body: some View {
        NavigationStack {
            Group {
                if let services = model.contactServices {
                    if byLink {
                        InviteByLinkContent(services: services)
                    } else {
                        InPersonContent(services: services)
                    }
                } else {
                    DeviceKeysUnavailableView()
                }
            }
            .navigationTitle(byLink ? Text("sharing.invite.byLink") : Text("sharing.verify.inPerson"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                        .accessibilityIdentifier("sharing.verify.cancel")
                }
            }
        }
        .onDisappear { Task { await model.refreshSharing() } }
    }
}

/// In person, over the `_onepass-contact._tcp` service.
private struct InPersonContent: View {
    @Environment(AppModel.self) private var model
    let services: ContactServices
    @StateObject private var holder = FlowHolder()
    @State private var scanning = false

    var body: some View {
        Form {
            if let flow = holder.flow {
                FlowStateView(flow: flow)
            } else {
                Section {
                    Button("sharing.verify.showCode") { start()?.showCode() }
                        .accessibilityIdentifier("sharing.verify.showCode")
                    #if os(iOS)
                    Button("sharing.verify.scanCode") { scanning = true }
                        .accessibilityIdentifier("sharing.verify.scanCode")
                    #endif
                }
            }
        }
        #if os(iOS)
        .sheet(isPresented: $scanning) {
            SecretKeyScanner(onKey: { text in
                scanning = false
                start()?.scan(qrText: text)
            }, accept: { $0 })
        }
        #endif
    }

    private func start() -> ContactVerificationFlow? {
        let name = model.settings.displayName
        let flow = model.session.contactVerificationFlow(myName: name, keys: services.keys, creator: services.creator)
        holder.flow = flow
        return flow
    }

    @MainActor final class FlowHolder: ObservableObject {
        @Published var flow: ContactVerificationFlow?
    }
}

/// The states of an in-person verification.
private struct FlowStateView: View {
    @ObservedObject var flow: ContactVerificationFlow

    var body: some View {
        switch flow.state {
        case .idle, .scanning, .exchanging:
            Section { ProgressView().frame(maxWidth: .infinity) }
        case .showingQR(let text):
            Section {
                if let image = PairingQRView.image(text, side: 600) {
                    Image(decorative: image, scale: 1)
                        .interpolation(.none)
                        .resizable()
                        .aspectRatio(1, contentMode: .fit)
                        .frame(maxWidth: 260)
                        .frame(maxWidth: .infinity)
                        .accessibilityIdentifier("sharing.verify.qr")
                }
            }
        case .comparing(let sas):
            Section {
                Text(sas)
                    .font(.system(size: 34, weight: .bold, design: .monospaced))
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("sharing.verify.sas")
            } footer: {
                Text("sharing.verify.compare")
            }
            Section {
                Button("sharing.verify.same") { flow.confirm() }
                    .accessibilityIdentifier("sharing.verify.same")
                Button("sharing.verify.different", role: .destructive) { flow.reject() }
                    .accessibilityIdentifier("sharing.verify.different")
            }
        case .done(let contact):
            Section {
                Label {
                    Text(contact.nameLocal)
                } icon: {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                }
            }
        case .failed(let failure):
            Section {
                Label(failure.message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }
}

/// By link: a new invitation shared with the system share sheet; the answer is awaited.
private struct InviteByLinkContent: View {
    @Environment(AppModel.self) private var model
    let services: ContactServices
    @StateObject private var holder = InviteHolder()

    var body: some View {
        Form {
            if let flow = holder.flow {
                InviteStateView(flow: flow)
            } else {
                Section {
                    Button("sharing.invite.create") {
                        let flow = model.session.contactInviteFlow(
                            myName: model.settings.displayName, drops: services.drops,
                            creator: services.creator, hosted: services.hosted)
                        holder.flow = flow
                        flow.createInvite()
                    }
                    .accessibilityIdentifier("sharing.invite.create")
                } footer: {
                    Text("sharing.invite.footer")
                }
            }
        }
    }

    @MainActor final class InviteHolder: ObservableObject {
        @Published var flow: ContactInviteFlow?
    }
}

private struct InviteStateView: View {
    @ObservedObject var flow: ContactInviteFlow

    var body: some View {
        switch flow.state {
        case .idle, .waitingForUnlock, .waitingForAnswer:
            Section { Label("sharing.invite.waiting", systemImage: "hourglass") }
        case .sharing(let link, _):
            Section {
                ShareLink(item: link) { Label("sharing.invite.share", systemImage: "square.and.arrow.up") }
                    .accessibilityIdentifier("sharing.invite.share")
                Label("sharing.invite.waiting", systemImage: "hourglass").foregroundStyle(.secondary)
            }
        case .done(let contact):
            Section {
                HStack {
                    Text(contact.nameLocal)
                    Spacer(minLength: 0)
                    UnverifiedBadge()
                }
            }
        case .failed(let message):
            Section {
                Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }
}
