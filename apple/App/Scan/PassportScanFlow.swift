#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit
import VisionKit

/// The passport scan on iPhone (NFC documents spec 6.2): the camera finds the two MRZ lines, the
/// phone goes on the document, Core NFC reads the chip, the booklet reveals what it read, then
/// "Enregistrer". Leaving the screen cancels a read in progress, which closes the system sheet.
struct PassportScanFlow: View {
    @Environment(AppModel.self) private var app
    @State private var model: PassportScanModel
    @State private var readTask: Task<Void, Never>?

    init(target: ScanTarget, session: VaultSession) {
        _model = State(initialValue: PassportScanModel(target: target, session: session) {
            () throws(PassportReadError) -> any PassportChipLink in
            try ChipLinks.make()
        })
    }

    var body: some View {
        Group {
            switch model.phase {
            case .camera:
                ScanCameraStep { model.mrzFound($0) }
            case .place:
                ScanPlaceStep(model: model) { startRead() }
            case .reading(let progress):
                ScanReadingStep(progress: progress)
            case .reveal(let item, let portrait):
                ScanRevealStep(model: model, item: item, portrait: portrait)
            case .failed(let error):
                ScanFailureStep(error: error, canKeepMRZ: canKeepMRZ) { action in handle(action) }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .modifier(ScanCaptureMask())
        .animation(.easeOut(duration: 0.2), value: phaseKey)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("common.close", systemImage: "xmark") { app.finishScan(nil) }
                    .accessibilityIdentifier("scan.close")
            }
        }
        .navigationTitle(Text(title))
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { readTask?.cancel() }
    }

    private var title: LocalizedStringKey {
        if case .merge = model.target { "scan.title.rescan" } else { "scan.title.passport" }
    }

    /// The step, for the transition between screens (not the progress inside one).
    private var phaseKey: Int {
        switch model.phase {
        case .camera: 0
        case .place: 1
        case .reading: 2
        case .reveal: 3
        case .failed: 4
        }
    }

    /// A new passport can be made from the MRZ alone; a later read of a stored one cannot.
    private var canKeepMRZ: Bool {
        if case .new = model.target { model.mrz != nil } else { false }
    }

    private func startRead() {
        readTask?.cancel()
        readTask = Task { await model.readChip() }
    }

    private func handle(_ action: ScanFailureStep.Action) {
        switch action {
        case .rescan: model.rescan()
        case .retry: startRead()
        case .keepMRZ:
            Task {
                if let item = await model.mrzOnlyItem() { app.editScannedDraft(item) }
            }
        }
    }
}

/// The flow shows the document, its MRZ and the read: while the screen is recorded, mirrored or
/// AirPlayed (`isSceneCaptured`) it is hidden, as revealed secrets are elsewhere in the app, and it
/// is marked privacy sensitive. The app switcher is covered by the app's `PrivacyShield` window,
/// which sits above this full screen cover too.
private struct ScanCaptureMask: ViewModifier {
    @Environment(\.isSceneCaptured) private var captured

    func body(content: Content) -> some View {
        content
            .privacySensitive()
            .opacity(captured ? 0 : 1)
            .accessibilityHidden(captured)
            .overlay {
                if captured {
                    Label("scan.hiddenWhileCaptured", systemImage: "eye.slash")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(Theme.Space.l)
                        .accessibilityIdentifier("scan.captureMask")
                }
            }
    }
}

// MARK: - Camera

/// "Montre la page avec ta photo": the camera reads the MRZ. After 20 s without it, or when the
/// camera cannot start, "Saisir les lignes" lets the user type them.
private struct ScanCameraStep: View {
    let onMRZ: @MainActor ([String]) -> Void
    @State private var stuck = false
    @State private var cameraFailed = false
    @State private var typing = false

    private static let patience: Duration = .seconds(20)

    var body: some View {
        if typing {
            ManualMRZEntry(onMRZ: onMRZ)
        } else {
            VStack(spacing: Theme.Space.l) {
                camera
                    .aspectRatio(PassportFace.aspectRatio, contentMode: .fit)
                    .clipShape(.rect(cornerRadius: 18, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .strokeBorder(.white.opacity(0.8), lineWidth: 2)
                    }
                    .overlay(alignment: .bottom) {
                        // Where the two lines go.
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .strokeBorder(.white.opacity(0.9), style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                            .frame(height: 44)
                            .padding(12)
                            .accessibilityHidden(true)
                    }
                    .padding(.horizontal, Theme.Space.l)
                    .accessibilityIdentifier("scan.camera")
                Text("scan.camera.instruction")
                    .font(.title3.weight(.semibold))
                    .multilineTextAlignment(.center)
                if stuck || cameraFailed {
                    VStack(spacing: Theme.Space.m) {
                        Text(cameraFailed ? "scan.camera.unavailable" : "scan.camera.stuck")
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .accessibilityIdentifier("scan.camera.stuck")
                        Button("scan.camera.typeLines") { typing = true }
                            .buttonStyle(.borderedProminent)
                            .accessibilityIdentifier("scan.typeLines")
                    }
                    .transition(.opacity)
                }
                Spacer(minLength: 0)
            }
            .padding(.top, Theme.Space.l)
            .padding(.horizontal, Theme.Space.l)
            .task {
                try? await Task.sleep(for: Self.patience)
                if !Task.isCancelled { withAnimation { stuck = true } }
            }
        }
    }

    @ViewBuilder private var camera: some View {
        if ChipLinks.isFake {
            fakeCamera
        } else if DataScannerViewController.isSupported, DataScannerViewController.isAvailable {
            MRZScanner(onMRZ: onMRZ) { _ in withAnimation { cameraFailed = true } }
        } else {
            Color.black.onAppear { cameraFailed = true }
        }
    }

    /// UI tests: the camera reads a fixed MRZ after a moment.
    @ViewBuilder private var fakeCamera: some View {
        #if DEBUG
        Color.black.task {
            try? await Task.sleep(for: .milliseconds(800))
            if !Task.isCancelled { onMRZ(FakeChipLink.cameraMRZ) }
        }
        #else
        Color.black
        #endif
    }
}

/// "Saisir les lignes": the two lines typed, accepted once their check digits pass.
private struct ManualMRZEntry: View {
    let onMRZ: @MainActor ([String]) -> Void
    @State private var first = ""
    @State private var second = ""
    @FocusState private var focused: Int?

    private static func clean(_ s: String) -> String {
        s.uppercased().filter { !$0.isWhitespace }
    }

    private var parsed: FfiMrz? {
        let lines = [Self.clean(first), Self.clean(second)]
        guard lines.allSatisfy({ $0.count == 44 }) else { return nil }
        return try? mrzParse(lines: lines)
    }

    private var complete: Bool { Self.clean(first).count == 44 && Self.clean(second).count == 44 }

    var body: some View {
        Form {
            Section {
                line($first, index: 0, id: "scan.manual.line1")
                line($second, index: 1, id: "scan.manual.line2")
            } header: {
                Text("scan.manual.title")
            } footer: {
                if complete, parsed == nil {
                    Text("scan.manual.invalid")
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("scan.manual.invalid")
                } else {
                    Text("scan.manual.footer")
                }
            }
            Section {
                Button("common.continue") {
                    if let parsed { onMRZ(parsed.lines) }
                }
                .disabled(parsed == nil)
                .accessibilityIdentifier("scan.manual.continue")
            }
        }
        .onAppear { focused = 0 }
    }

    private func line(_ text: Binding<String>, index: Int, id: String) -> some View {
        TextField(index == 0 ? "scan.manual.line1" : "scan.manual.line2", text: text, axis: .vertical)
            .font(.system(.footnote, design: .monospaced))
            .textInputAutocapitalization(.characters)
            .autocorrectionDisabled()
            .keyboardType(.asciiCapable)
            // Never offered to AutoFill or the keyboard's suggestions, hidden from captures.
            .textContentType(nil)
            .privacySensitive()
            .focused($focused, equals: index)
            .onSubmit { focused = index == 0 ? 1 : nil }
            .accessibilityIdentifier(id)
    }
}

// MARK: - Place and read

/// "Pose ton téléphone sur le document.": a preview of the document filled from the MRZ alone
/// (no portrait, no chip status), the top of the iPhone's back coming down onto it, then "Lire la
/// puce" opens the system NFC sheet (spec 6.2 step 2).
private struct ScanPlaceStep: View {
    let model: PassportScanModel
    let onRead: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var lowered = false
    @State private var preview: FfiItem?
    @State private var previewOpen = true

    private var family: DocumentFamily {
        if let preview { return PassportBooklet.family(of: preview) }
        let state = (try? mrzParse(lines: model.mrz ?? []))?.issuingState ?? ""
        return .passport(issuingCountry: state)
    }

    var body: some View {
        VStack(spacing: Theme.Space.xl) {
            Spacer(minLength: 0)
            ZStack(alignment: .top) {
                PassportFace(
                    family: family, data: preview.map { PassportBooklet.data(of: $0, portrait: nil) } ?? PassportData(),
                    isOpen: $previewOpen, secretsRevealed: false)
                    .frame(maxWidth: 300)
                    .allowsHitTesting(false)
                    .accessibilityIdentifier("scan.place.preview")
                // The phone, back up, comes down onto the top of the page.
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(.background)
                    .overlay {
                        RoundedRectangle(cornerRadius: 22, style: .continuous)
                            .strokeBorder(.primary.opacity(0.7), lineWidth: 2.5)
                    }
                    .overlay(alignment: .topLeading) {
                        // The camera bump marks the top of the back.
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(.primary.opacity(0.6), lineWidth: 2)
                            .frame(width: 34, height: 34)
                            .padding(8)
                    }
                    .frame(width: 92, height: 180)
                    .offset(x: 60, y: lowered ? -96 : -150)
                    .opacity(0.95)
                    .accessibilityElement()
                    .accessibilityLabel(Text("scan.place.illustration"))
            }
            .frame(height: 340, alignment: .bottom)
            .padding(.horizontal, Theme.Space.l)
            VStack(spacing: Theme.Space.s) {
                Text("scan.place.title")
                    .font(.title3.weight(.semibold))
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("scan.place.title")
                Text("scan.place.hint")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, Theme.Space.l)
            Spacer(minLength: 0)
            Button(action: onRead) {
                Text("scan.place.read").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, Theme.Space.l)
            .padding(.bottom, Theme.Space.l)
            .accessibilityIdentifier("scan.read")
        }
        .task(id: model.mrz) { preview = await model.mrzItem() }
        .onAppear {
            guard !reduceMotion else {
                lowered = true
                return
            }
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) { lowered = true }
        }
    }
}

/// While the system sheet reads: the same progress as its "Lecture de la puce, N %".
private struct ScanReadingStep: View {
    let progress: Double

    var body: some View {
        VStack(spacing: Theme.Space.l) {
            Spacer(minLength: 0)
            ProgressView(value: progress)
                .frame(maxWidth: 260)
            Text(verbatim: PassportScanModel.alertMessage(progress: progress))
                .font(.headline)
                .monospacedDigit()
                .accessibilityIdentifier("scan.reading")
            Text("scan.reading.hint")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer(minLength: 0)
        }
        .padding(Theme.Space.l)
    }
}

// MARK: - Reveal

/// The booklet fills in with what the chip gave (portrait, rows, then the badge), the conflicts of
/// a later read with the user's values, the vault, and "Enregistrer".
private struct ScanRevealStep: View {
    @Environment(AppModel.self) private var app
    @Bindable var model: PassportScanModel
    let item: FfiItem
    let portrait: Data?
    @State private var isOpen = true
    @State private var revealProgress = 0.0
    @State private var vaultID: String = ""
    @State private var saving = false
    @State private var saveError: String?

    private var image: Image? {
        guard let portrait, let ui = UIImage(data: portrait) else { return nil }
        return Image(uiImage: ui)
    }

    private var isNew: Bool {
        if case .new = model.target { true } else { false }
    }

    private var vaults: [FfiVault] { app.session.vaults }

    private var accent: Color? {
        app.session.allVaults.first { $0.id == (isNew ? vaultID : item.vaultId) }
            .map { VaultBadge.color(named: $0.meta.color) }
    }

    var body: some View {
        let data = PassportBooklet.data(of: item, portrait: image)
        ScrollView {
            VStack(spacing: Theme.Space.l) {
                PassportFace(
                    family: PassportBooklet.family(of: item), data: data, isOpen: $isOpen,
                    revealProgress: revealProgress, secretsRevealed: false)
                    .documentAccent(accent)
                    .frame(maxWidth: 440)
                    .accessibilityIdentifier("scan.booklet")
                if let status = data.status, let readOn = data.readOn {
                    ChipBadge(status: status, readOn: readOn)
                        .frame(maxWidth: 440, alignment: .leading)
                        .opacity(revealProgress >= 1 ? 1 : 0)
                        .accessibilityIdentifier("scan.badge")
                }
                if !model.conflicts.isEmpty {
                    conflicts
                }
                if isNew, vaults.count > 1 {
                    // Once the passport is stored, it stays in that vault (a retry resumes it).
                    VaultPicker(vaultID: $vaultID)
                        .frame(maxWidth: 440, alignment: .leading)
                        .disabled(model.savedVaultID != nil)
                }
                if let saveError {
                    Text(saveError)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("scan.saveError")
                }
                Button {
                    save()
                } label: {
                    Text("common.save").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: 440)
                .disabled(saving)
                .accessibilityIdentifier("scan.save")
            }
            .padding(Theme.Space.l)
            .frame(maxWidth: .infinity)
        }
        .onAppear {
            if vaultID.isEmpty { vaultID = item.vaultId }
            withAnimation(.linear(duration: PassportFace.revealDuration)) { revealProgress = 1 }
        }
    }

    /// A later read that disagrees with what the user typed: both values, theirs kept by default.
    private var conflicts: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Text("scan.conflicts.title")
                .font(.headline)
            Text("scan.conflicts.body")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            ForEach(model.conflicts, id: \.fieldId) { conflict in
                VStack(alignment: .leading, spacing: Theme.Space.xs) {
                    Text(verbatim: label(of: conflict.fieldId))
                        .font(.subheadline.weight(.semibold))
                    Picker(selection: choice(conflict.fieldId)) {
                        Text(verbatim: shown(conflict.stored, field: conflict.fieldId)).tag(false)
                        Text(verbatim: shown(conflict.scanned, field: conflict.fieldId)).tag(true)
                    } label: {
                        Text(verbatim: label(of: conflict.fieldId))
                    }
                    .pickerStyle(.segmented)
                    .privacySensitive()
                    .accessibilityIdentifier("scan.conflict.\(conflict.fieldId)")
                    Text(model.takeScanned.contains(conflict.fieldId) ? "scan.conflicts.chipKept" : "scan.conflicts.yoursKept")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(maxWidth: 440, alignment: .leading)
        .padding(Theme.Space.m)
        .background(.fill.quinary, in: .rect(cornerRadius: Theme.Radius.card, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("scan.conflicts")
    }

    private func choice(_ fieldID: String) -> Binding<Bool> {
        Binding(
            get: { model.takeScanned.contains(fieldID) },
            set: { take in
                if take { model.takeScanned.insert(fieldID) } else { model.takeScanned.remove(fieldID) }
            })
    }

    private func label(of fieldID: String) -> String {
        guard let field = item.sections.lazy.flatMap(\.fields).first(where: { $0.id == fieldID }) else {
            return fieldID
        }
        return CoreLabels.fieldLabel(field, itemType: item.itemType)
    }

    /// The number and the MRZ stay masked here too, but for their last characters.
    private func shown(_ value: String, field: String) -> String {
        guard field == "number" || field == "mrz" else { return value }
        return String(repeating: "•", count: 6) + value.suffix(3)
    }

    private func save() {
        guard !saving else { return }
        saving = true
        saveError = nil
        Task {
            defer { saving = false }
            do {
                let saved = try await model.save(vaultID: vaultID.isEmpty ? item.vaultId : vaultID)
                app.finishScan(saved)
            } catch {
                saveError = VaultError(error).localizedMessage
            }
        }
    }
}

// MARK: - Failures

/// The failures of spec 6.2, each with its way on.
private struct ScanFailureStep: View {
    enum Action { case rescan, retry, keepMRZ }

    let error: PassportReadError
    let canKeepMRZ: Bool
    let onAction: (Action) -> Void

    var body: some View {
        VStack(spacing: Theme.Space.l) {
            Spacer(minLength: 0)
            Image(systemName: symbol)
                .font(.system(size: 44, weight: .regular))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(verbatim: PassportScanModel.message(for: error))
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("scan.error")
            Spacer(minLength: 0)
            VStack(spacing: Theme.Space.s) {
                ForEach(actions, id: \.self) { action in
                    button(action)
                }
            }
            .padding(.bottom, Theme.Space.l)
        }
        .padding(.horizontal, Theme.Space.l)
    }

    private var symbol: String {
        switch error {
        case .accessDenied: "lock.slash"
        case .lostContact: "wave.3.right"
        case .noChip, .nfcUnavailable: "sensor.tag.radiowaves.forward"
        case .unsupported, .cancelled: "exclamationmark.triangle"
        }
    }

    /// The first one is the main action.
    private var actions: [Action] {
        switch error {
        case .accessDenied: [.rescan]
        case .lostContact, .cancelled: [.retry]
        case .noChip, .nfcUnavailable: canKeepMRZ ? [.keepMRZ, .rescan] : [.rescan]
        case .unsupported: canKeepMRZ ? [.retry, .keepMRZ] : [.retry]
        }
    }

    @ViewBuilder private func button(_ action: Action) -> some View {
        let button = Button {
            onAction(action)
        } label: {
            Text(title(action)).frame(maxWidth: .infinity)
        }
        .controlSize(.large)
        .accessibilityIdentifier(identifier(action))
        if action == actions.first {
            button.buttonStyle(.borderedProminent)
        } else {
            button.buttonStyle(.bordered)
        }
    }

    private func title(_ action: Action) -> LocalizedStringKey {
        switch action {
        case .rescan: "scan.action.rescan"
        case .retry: "common.tryAgain"
        case .keepMRZ: "scan.action.keepMRZ"
        }
    }

    private func identifier(_ action: Action) -> String {
        switch action {
        case .rescan: "scan.rescan"
        case .retry: "scan.retry"
        case .keepMRZ: "scan.keepMRZ"
        }
    }
}

#endif
