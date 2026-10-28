import SwiftUI
import VaultKit

/// The unlocked app. Mac, Vision Pro and iPad in regular width: `SplitBrowseView` (three columns). iPhone and
/// iPad in compact width (Split View, Slide Over): `PhoneTabsView`. Both share the guarded actions:
/// the ⌘N type picker and "Abandonner les modifications ?" before a lock or a navigation would
/// drop an edited draft.
struct BrowseRoot: View {
    @Environment(AppModel.self) private var model
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #endif

    var body: some View {
        @Bindable var model = model
        return layout
            #if os(iOS) || os(visionOS)
            // Réglages: a sheet everywhere, opened on iPhone from the account menu.
            .sheet(isPresented: settingsSheetShown) {
                SettingsView()
            }
            #endif
            // "Générer un mot de passe" Control (`onepass://generator`): the value is only copied.
            .sheet(isPresented: $model.showGenerator) {
                GeneratorSheet(
                    onUse: { value in
                        model.session.copy(value, concealed: true)
                        model.showToast(String(localized: "Copié · effacé dans 90 s"))
                    },
                    purpose: .copy)
            }
            // Fichier > Importer… (⌘⇧I): exports of other password managers.
            .sheet(isPresented: $model.showImport) {
                ImportSheet()
            }
            // Fichier > Restaurer une sauvegarde…: a OnePass archive (.onepass).
            .sheet(isPresented: $model.showRestore) {
                RestoreSheet()
            }
            // "Copier le code à usage unique" when the device cannot confirm the user itself.
            .sheet(item: $model.totpPasswordRequest) { ref in
                PasswordPromptSheet(
                    title: "Copier le code à usage unique",
                    footer: "Le mot de passe maître est demandé pour copier le code à usage unique."
                ) { password in
                    try await model.session.verifyMasterPassword(password)
                    await model.copyTotpCode(ref)
                }
                .onAppear { model.totpPromptShown = true }
            }
            // The split view shows a revealed item through the selection, and searches through
            // `searchFocusRequest`; the iPhone tabs handle the reveal themselves.
            .onChange(of: model.browseReveal, initial: true) { _, reveal in
                guard let reveal, !handlesRevealInTabs else { return }
                model.browseReveal = nil
                if reveal == .search {
                    // The list column may appear in this same update: asked again once it is there.
                    Task { model.searchFocusRequest &+= 1 }
                }
            }
            // On iPhone the new item sheet carries its own confirmation (shown over the sheet).
            .discardConfirmation(active: !phoneNewItemShown)
            .overlay(alignment: .bottom) {
                if let toast = model.toast {
                    ToastBanner(toast: toast)
                        .padding(.bottom, 18)
                        .transition(toastTransition)
                        .id(toast)
                }
            }
            .animation(toastAnimation, value: model.toast)
            // Not over the iPhone tabs: on iOS 27 this tap gesture swallows the taps of the navigation
            // links below it (rows, Réglages pages); the tabs note activity on navigation instead.
            .simultaneousGesture(
                TapGesture().onEnded { model.session.noteActivity() },
                including: handlesRevealInTabs ? .subviews : .all)
    }

    /// The toast rises from the bottom edge and leaves the same way. iPhone and iPad: a critically
    /// damped spring, and only a fade with Reduce Motion.
    private var toastTransition: AnyTransition {
        #if os(iOS)
        reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity)
        #else
        .move(edge: .bottom).combined(with: .opacity)
        #endif
    }

    private var toastAnimation: Animation {
        #if os(iOS)
        reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.35, bounce: 0)
        #else
        .snappy
        #endif
    }

    @ViewBuilder private var layout: some View {
        #if os(macOS) || os(visionOS)
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

    private var handlesRevealInTabs: Bool {
        #if os(iOS)
        usesTabs
        #else
        false
        #endif
    }

    private var settingsSheetShown: Binding<Bool> {
        Binding(
            // iPhone tabs too: Réglages left the tab bar for the account menu.
            get: { model.showSettings },
            set: { model.showSettings = $0 })
    }

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

/// The master password sheet of "Copier le code à usage unique" is presented for an item.
extension ItemRef: Identifiable {
    var id: Self { self }
}

/// What a notification reports: the icon and color follow it.
enum ToastKind: Equatable {
    case success, error, info
}

struct Toast: Equatable, Hashable {
    let text: String
    let kind: ToastKind
    /// Two identical messages in a row are two notifications.
    let id = UUID()
}

/// The notification capsule at the bottom of the window: an icon in the kind's color, the text.
struct ToastBanner: View {
    let toast: Toast

    private var symbol: String {
        switch toast.kind {
        case .success: "checkmark.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        case .info: "info.circle.fill"
        }
    }

    private var color: Color {
        switch toast.kind {
        case .success: .green
        case .error: .red
        case .info: .secondary
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(color)
                .font(.callout.weight(.semibold))
                .accessibilityHidden(true)
            Text(toast.text)
                .font(.callout.weight(.medium))
                .lineLimit(2)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        #if os(visionOS)
        .glassBackgroundEffect(in: Capsule())
        #else
        .glassEffect(.regular, in: Capsule())
        #endif
        .overlay {
            if toast.kind == .error { Capsule().strokeBorder(.red.opacity(0.45)) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isStaticText)
        .accessibilityIdentifier("browse.toast")
    }
}
