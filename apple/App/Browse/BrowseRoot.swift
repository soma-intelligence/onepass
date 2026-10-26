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
        layout
            // On iPhone the new item sheet carries its own confirmation (shown over the sheet).
            .discardConfirmation(active: !phoneNewItemShown)
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
        split
        #else
        if usesTabs {
            PhoneTabsView()
        } else {
            split
        }
        #endif
    }

    /// The split view and its ⌘N type picker (the iPhone tabs present their own new item sheet).
    private var split: some View {
        @Bindable var model = model
        return SplitBrowseView()
            .sheet(isPresented: $model.showNewItemPicker) {
                NewItemSheet()
            }
    }

    #if os(iOS)
    private var usesTabs: Bool { !(UIDevice.current.userInterfaceIdiom == .pad && sizeClass == .regular) }
    #endif

    private var phoneNewItemShown: Bool {
        #if os(iOS)
        usesTabs && (model.showNewItemPicker || model.newItemDraft != nil)
        #else
        false
        #endif
    }
}

extension View {
    /// "Abandonner les modifications ?" before a guarded action (`AppModel.perform`) drops an edited
    /// draft. `active` false leaves it to another presenter (a sheet on screen above this view).
    func discardConfirmation(active: Bool = true) -> some View {
        modifier(DiscardConfirmation(active: active))
    }
}

private struct DiscardConfirmation: ViewModifier {
    @Environment(AppModel.self) private var model
    let active: Bool

    func body(content: Content) -> some View {
        content.confirmationDialog(
            "Abandonner les modifications ?", isPresented: presented, titleVisibility: .visible
        ) {
            Button(model.pendingDiscard == .lock ? "Abandonner et verrouiller" : "Abandonner", role: .destructive) {
                model.confirmDiscard()
            }
            .accessibilityIdentifier("discard.confirm")
            Button("Continuer la modification", role: .cancel) { model.pendingDiscard = nil }
        } message: {
            Text("Les modifications de cet élément ne sont pas enregistrées.")
        }
    }

    private var presented: Binding<Bool> {
        Binding(
            get: { active && model.pendingDiscard != nil },
            set: { if !$0 { model.pendingDiscard = nil } })
    }
}
