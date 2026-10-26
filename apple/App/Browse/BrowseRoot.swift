import SwiftUI
import VaultKit

/// The unlocked app. Mac and iPad in regular width: `SplitBrowseView` (three columns). iPhone and
/// iPad in compact width (Split View, Slide Over): `PhoneTabsView`. Both share the guarded actions:
/// the ⌘N type picker and "Abandonner les modifications ?" before a lock or a navigation would
/// drop an edited draft.
struct BrowseRoot: View {
    @Environment(AppModel.self) private var model
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    var body: some View {
        @Bindable var model = model
        layout
            .sheet(isPresented: $model.showNewItemPicker) {
                NewItemSheet()
            }
            .confirmationDialog(
                "Abandonner les modifications ?", isPresented: discardPresented, titleVisibility: .visible
            ) {
                Button(model.pendingDiscard == .lock ? "Abandonner et verrouiller" : "Abandonner", role: .destructive) {
                    model.confirmDiscard()
                }
                .accessibilityIdentifier("discard.confirm")
                Button("Continuer la modification", role: .cancel) { model.pendingDiscard = nil }
            } message: {
                Text("Les modifications de cet élément ne sont pas enregistrées.")
            }
            .overlay(alignment: .bottom) {
                if let toast = model.toast {
                    Text(toast)
                        .font(.footnote.weight(.medium))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 9)
                        .glassEffect(.regular, in: Capsule())
                        .padding(.bottom, 18)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .accessibilityIdentifier("browse.toast")
                }
            }
            .animation(.snappy, value: model.toast)
            .simultaneousGesture(TapGesture().onEnded { model.session.noteActivity() })
    }

    @ViewBuilder private var layout: some View {
        #if os(macOS)
        SplitBrowseView()
        #else
        if UIDevice.current.userInterfaceIdiom == .pad, sizeClass == .regular {
            SplitBrowseView()
        } else {
            PhoneTabsView()
        }
        #endif
    }

    private var discardPresented: Binding<Bool> {
        Binding(
            get: { model.pendingDiscard != nil },
            set: { if !$0 { model.pendingDiscard = nil } })
    }
}
