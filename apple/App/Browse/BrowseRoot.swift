import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// The unlocked app. Mac, Vision Pro and iPad in regular width: `SplitBrowseView` (three columns). iPhone and
/// iPad in compact width (Split View, Slide Over): `PhoneTabsView`. Both share the guarded actions:
/// the ⌘N type picker and "Abandonner les modifications ?" before a lock or a navigation would
/// drop an edited draft.
struct BrowseRoot: View {
    @Environment(AppModel.self) private var model
    /// The RX look shows every toast through DesignBridgeKit (`RXToastBridge`).
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The window's width: an unfolded iPhone gets the two-pane layout.
    @State private var width: CGFloat = 0
    #endif

    var body: some View {
        @Bindable var model = model
        return layout
            #if os(iOS) || os(visionOS)
            // Réglages: a sheet everywhere, opened on iPhone from the account menu.
            .sheet(isPresented: settingsAsSheet) {
                SettingsView()
            }
            #endif
            #if os(iOS)
            // RX: Réglages full screen and see-through, the screen under it blurred by each page
            // (RXFrostedBackdrop), as in the owner's reference.
            .fullScreenCover(isPresented: rxDesign ? settingsSheetShown : .constant(false)) {
                SettingsView()
                    .modifier(RXReadableWidth())
                    .presentationBackground(.clear)
            }
            #endif
            // "Générer un mot de passe" Control (`onepass://generator`): the value is only copied.
            .sheet(isPresented: $model.showGenerator) {
                GeneratorSheet(
                    onUse: { value in
                        model.session.copy(value, concealed: true)
                        model.showToast(String(localized: "app.copiedClearedIn90"))
                    },
                    purpose: .copy)
            }
            // "Tu voyages ?" > Oui, or "De retour ?" > Désactiver (spec 2026-11-02).
            .sheet(item: $model.travelSheet) { request in
                NavigationStack {
                    TravelSettings(autoConfirm: request == .enter)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Fermer") { model.travelSheet = nil }
                            }
                        }
                }
                #if os(macOS)
                .frame(minWidth: 460, minHeight: 520)
                #endif
            }
            // Fichier > Importer… (⌘⇧I): exports of other password managers.
            .sheet(isPresented: $model.showImport) {
                ImportSheet()
            }
            #if os(macOS)
            // Account menu > Configurer un appareil…: the Mac shows the code, the new device scans it.
            .sheet(isPresented: $model.showDeviceSetup) {
                ApproveDeviceSheet()
            }
            #endif
            // Fichier > Restaurer une sauvegarde…: a Cleon archive (.onepass).
            .sheet(isPresented: $model.showRestore) {
                RestoreSheet()
            }
            #if os(macOS)
            // Fichier > Configurer un appareil… : the pairing code for a new device.
            .sheet(isPresented: $model.showHostDevice) {
                HostDeviceSheet()
            }
            #endif
            // "Copier le code à usage unique" when the device cannot confirm the user itself.
            .sheet(item: $model.totpPasswordRequest) { ref in
                PasswordPromptSheet(
                    title: "Copier le code à usage unique",
                    footer: "browse.masterPasswordRequiredTo"
                ) { password in
                    try await model.session.verifyMasterPassword(password)
                    await model.copyTotpCode(ref)
                }
                .onAppear { model.totpPromptShown = true }
            }
            // A verification code link (`otpauth://`, `otpauth-migration://`) or a scanned code.
            .sheet(item: $model.otpLinkRequest) { request in
                AddOtpSheet(request: request)
            }
            #if os(iOS)
            // Scanner (new item sheet) and Scanner la puce (a passport's detail): camera, chip, save.
            .fullScreenCover(item: $model.scanRequest, onDismiss: { model.scanCoverDismissed() }) { request in
                ScanCover(request: request)
            }
            .sheet(isPresented: $model.showOtpScanner) {
                SecretKeyScannerSheet(title: "Code de vérification", accept: SecretKeyScanner.acceptOtpLink) { link in
                    Task { await model.presentOtpLink(link, source: .scan) }
                }
            }
            #endif
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
                if !rxDesign, let toast = model.toast {
                    ToastBanner(toast: toast)
                        .padding(.bottom, 18)
                        .transition(toastTransition)
                        .id(toast)
                }
            }
            .animation(toastAnimation, value: model.toast)
            .modifier(RXToastBridge(active: rxDesign))
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
        Group {
            if usesTabs {
                PhoneTabsView()
                    .transition(.opacity)
            } else if isFold {
                foldSplit
                    .transition(.opacity)
            } else {
                split
            }
        }
        // Folding or unfolding swaps the layouts; the unfolded one plays its own entrance.
        .animation(reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.4, bounce: 0), value: isFold)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        #endif
    }

    #if os(iOS)
    /// The unfolded iPhone: the phone's tabs and the detail side by side. The tabs present the
    /// new item sheet themselves, as on the folded phone.
    private var foldSplit: some View {
        FoldSplitView()
    }
    #endif

    /// The split view and its ⌘N type picker (the iPhone tabs present their own new item sheet).
    private var split: some View {
        @Bindable var model = model
        return SplitBrowseView()
            .sheet(isPresented: $model.showNewItemPicker) {
                NewItemSheet()
            }
    }

    #if os(iOS)
    /// An unfolded iPhone: the iPhone Duo's inner screen is 669 pt wide in portrait, its cover
    /// screen 466 pt, and no other iPhone passes 440 pt in portrait (iPhone is portrait only).
    /// `-OnePassFoldLayout YES` forces it in Debug on any window at least as wide.
    private var isFold: Bool {
        #if DEBUG
        if UserDefaults.standard.bool(forKey: "OnePassFoldLayout") { return width >= FoldLayout.minWidth }
        #endif
        return UIDevice.current.userInterfaceIdiom == .phone && FoldLayout.isUnfolded(width: width)
    }

    private var usesTabs: Bool {
        if isFold { return false }
        return !(UIDevice.current.userInterfaceIdiom == .pad && sizeClass == .regular)
    }
    #endif

    private var handlesRevealInTabs: Bool {
        #if os(iOS)
        usesTabs || isFold
        #else
        false
        #endif
    }

    /// Réglages as a sheet: everywhere but the RX iPhone, which covers the full screen.
    private var settingsAsSheet: Binding<Bool> {
        #if os(iOS)
        rxDesign ? .constant(false) : settingsSheetShown
        #else
        settingsSheetShown
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
        (usesTabs || isFold) && (model.showNewItemPicker || model.newItemDraft != nil)
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
            Button("app.keepEditing", role: .cancel) { model.pendingDiscard = nil }
        } message: {
            Text("browse.changesToItemArent")
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
    /// Undo or Retry: a button in the toast that runs the handler and closes it.
    var action: ToastAction?
    /// Two identical messages in a row are two notifications.
    let id = UUID()

    static func == (lhs: Toast, rhs: Toast) -> Bool { lhs.id == rhs.id }

    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

/// The button of a toast. `undo` and `retry` map to the DesignBridgeKit factories of the RX look.
struct ToastAction: Sendable {
    enum Kind: Sendable { case undo, retry, other }

    let kind: Kind
    let title: String
    let handler: @MainActor @Sendable () -> Void
    /// The screen the button acts on (an item editor). `AppModel.dropToastActions(owner:)` drops
    /// the button when that screen closes, with the values its handler captured.
    var owner: ObjectIdentifier?

    /// Undo of a reversible action (archive, trash, a removed field...).
    static func undo(owner: AnyObject? = nil, _ handler: @escaping @MainActor @Sendable () -> Void) -> ToastAction {
        ToastAction(kind: .undo, title: DBStrings.undo, handler: handler, owner: owner.map(ObjectIdentifier.init))
    }

    /// Try again after a failure.
    static func retry(_ handler: @escaping @MainActor @Sendable () -> Void) -> ToastAction {
        ToastAction(kind: .retry, title: DBStrings.retry, handler: handler)
    }
}

/// The notification capsule at the bottom of the window: an icon in the kind's color, the text.
struct ToastBanner: View {
    @Environment(AppModel.self) private var model
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
            if let action = toast.action {
                Button(action.title) {
                    model.dismissToast()
                    action.handler()
                }
                .font(.callout.weight(.semibold))
                .buttonStyle(.borderless)
                .frame(minHeight: Theme.RX.Metrics.minTapTarget)
                .contentShape(.rect)
                .accessibilityIdentifier("browse.toast.action")
            }
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
        // With a button, its children stay reachable (VoiceOver can press Undo).
        .accessibilityElement(children: toast.action == nil ? .combine : .contain)
        .accessibilityAddTraits(toast.action == nil ? .isStaticText : [])
        .accessibilityIdentifier("browse.toast")
    }
}

/// RX look: every `model.showToast` (copied, saved, every error) goes to the DesignBridgeKit host
/// at the root (`rxBridgeRoot`): one glass toast under the navigation bar, announced, with haptics, success
/// 1.8 s and errors 6 s. The classic banner stays for the classic look.
private struct RXToastBridge: ViewModifier {
    @Environment(AppModel.self) private var model
    @Environment(\.toast) private var toast
    let active: Bool

    func body(content: Content) -> some View {
        // Initial too: a toast set just before the browse screens appear (a link handled right
        // after the unlock) still reaches the host.
        // The model remembers what it already handed over: a bridge that appears again (tab switch,
        // rebuild) never shows the same toast twice or runs its Undo twice.
        content.onChange(of: model.toast, initial: true) { _, shown in
            guard active, let shown, model.forwardToast(shown) else { return }
            toast(Self.toast(for: shown, model: model))
        }
    }

    /// The host gets a lookup by toast id, never the handler itself: a lock empties the model's
    /// table, so a late tap does nothing and the captured values are released.
    static func toast(for shown: Toast, model: AppModel) -> DBToast {
        if let action = shown.action {
            let id = shown.id
            let handler: @MainActor @Sendable () -> Void = { [weak model] in model?.runToastAction(id) }
            switch action.kind {
            case .undo:
                return .undo(shown.text, undoTitle: action.title, perform: handler)
            case .retry:
                return .retry(shown.text, retryTitle: action.title, perform: handler)
            case .other:
                let button = DBToastButton(action.title, handler: handler)
                switch shown.kind {
                case .success: return .success(shown.text, action: button)
                case .error: return .error(shown.text, action: button)
                case .info: return .info(shown.text, action: button)
                }
            }
        }
        switch shown.kind {
        case .success: return .success(shown.text)
        case .error: return .error(shown.text)
        case .info: return .info(shown.text)
        }
    }
}

#if os(iOS)
/// RX Réglages on iPad: full screen, but the pages' rows keep a readable column in the middle
/// instead of running the width of a 13-inch screen. The frosted backdrop still fills the screen:
/// only the scroll content gets the margins (they reach every page pushed inside).
private struct RXReadableWidth: ViewModifier {
    @Environment(\.horizontalSizeClass) private var sizeClass
    private static let column: CGFloat = 640

    func body(content: Content) -> some View {
        GeometryReader { proxy in
            let side = sizeClass == .regular ? max(0, (proxy.size.width - Self.column) / 2) : 0
            content
                .contentMargins(.horizontal, side, for: .scrollContent)
                .environment(\.rxSettingsSideMargin, side)
        }
    }
}
#endif
