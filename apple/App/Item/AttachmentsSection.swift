import DesignKit
import PDFKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// "Pièces jointes" of an item's detail, for every item type: the files kept with it (a contract, an
/// invoice, a scan), each encrypted with its own key and synced with the item. A row opens an in-app
/// preview (PDF, image), the menu exports or deletes it, and "Ajouter un fichier…" attaches a new
/// one (20 Mo at most). Decrypted bytes live in memory only, never in a temporary file; exporting
/// writes them where the user chooses.
struct ItemAttachmentsSection: View {
    @Environment(AppModel.self) private var model
    let item: FfiItem
    /// Adding and deleting are offered (not in the trash, not in a read-only window).
    let editable: Bool
    /// The item as stored after a change.
    let onUpdate: (FfiItem) -> Void

    @State private var picking = false
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var preview: AttachmentPreviewRequest?
    @State private var exporting: AttachmentFile?
    @State private var confirmRemove: FfiAttachment?

    private var session: VaultSession { model.session }

    var body: some View {
        if !item.attachments.isEmpty || editable {
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text(String(localized: "item.attachments").uppercased())
                    .font(.caption.weight(.bold))
                    .tracking(0.6)
                    .foregroundStyle(.secondary)
                    .padding(.leading, Theme.Space.l)
                    .accessibilityAddTraits(.isHeader)
                EditorCard {
                    ForEach(Array(item.attachments.enumerated()), id: \.element.id) { index, attachment in
                        if index > 0 { CardDivider() }
                        row(attachment)
                    }
                    if editable {
                        if !item.attachments.isEmpty { CardDivider() }
                        addButton
                    }
                    if let errorMessage {
                        CardDivider()
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .foregroundStyle(.red)
                            .editorRowPadding()
                            .accessibilityIdentifier("item.attachments.error")
                    }
                }
                .disabled(busy)
                .overlay { if busy { ProgressView().controlSize(.small) } }
            }
            .accessibilityIdentifier("item.attachments")
            #if DEBUG
            .task(id: item.attachments.first?.id) {
                // Captures (`-OnePassDebugAttachmentPreview YES`): the first file opens in the preview.
                if UserDefaults.standard.bool(forKey: "OnePassDebugAttachmentPreview"), preview == nil,
                    let first = item.attachments.first
                {
                    try? await Task.sleep(for: .seconds(2))
                    await open(first, then: .preview)
                }
            }
            #endif
            .fileImporter(isPresented: $picking, allowedContentTypes: [.item]) { result in
                if case .success(let url) = result { Task { await attach(url) } }
            }
            .fileExporter(
                isPresented: Binding(get: { exporting != nil }, set: { if !$0 { exporting = nil } }),
                document: exporting,
                contentType: exporting?.type ?? .data,
                defaultFilename: exporting?.name
            ) { _ in exporting = nil }
            .sheet(item: $preview) { request in
                AttachmentPreviewSheet(request: request) { exporting = AttachmentFile(request) }
            }
            .confirmationDialog(
                "Supprimer « \(confirmRemove?.name ?? "") » ?",
                isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } }),
                titleVisibility: .visible
            ) {
                Button("item.deleteFile", role: .destructive) {
                    if let a = confirmRemove { Task { await remove(a) } }
                }
                .accessibilityIdentifier("item.attachment.remove.confirm")
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("item.fileRemovedFromItem")
            }
        }
    }

    private func row(_ attachment: FfiAttachment) -> some View {
        HStack(spacing: Theme.Space.m) {
            Button {
                Task { await open(attachment, then: .preview) }
            } label: {
                HStack(spacing: Theme.Space.m) {
                    Image(systemName: Self.symbol(of: attachment))
                        .font(.title3)
                        .foregroundStyle(Theme.readableAccent)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                        Text(attachment.name)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(ByteCountFormatter.string(fromByteCount: Int64(clamping: attachment.size), countStyle: .file))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    Spacer(minLength: 0)
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("item.attachment.open")
            Menu {
                Button("item.preview", systemImage: "eye") { Task { await open(attachment, then: .preview) } }
                Button("item.export", systemImage: "square.and.arrow.up") { Task { await open(attachment, then: .export) } }
                if editable {
                    Divider()
                    Button("item.delete", systemImage: "trash", role: .destructive) { confirmRemove = attachment }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .fixedSize()
            .accessibilityLabel("item.fileActions")
            .accessibilityIdentifier("item.attachment.menu")
        }
        .editorRowPadding()
    }

    private var addButton: some View {
        Button {
            errorMessage = nil
            picking = true
        } label: {
            Label("item.addFile", systemImage: "paperclip")
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .foregroundStyle(Theme.readableAccent)
        .editorRowPadding()
        .disabled(item.attachments.count >= 32)
        .accessibilityIdentifier("item.attachment.add")
    }

    static func symbol(of a: FfiAttachment) -> String {
        let type = UTType(mimeType: a.mime) ?? UTType(filenameExtension: (a.name as NSString).pathExtension)
        if type?.conforms(to: .pdf) == true { return "doc.richtext" }
        if type?.conforms(to: .image) == true { return "photo" }
        return "doc"
    }

    // MARK: - Actions

    private enum Then { case preview, export }

    private func open(_ attachment: FfiAttachment, then: Then) async {
        errorMessage = nil
        busy = true
        defer { busy = false }
        do {
            let data = try await session.attachmentData(
                itemID: item.id, vaultID: item.vaultId, attachmentID: attachment.id)
            let request = AttachmentPreviewRequest(attachment: attachment, data: data)
            switch then {
            case .preview: preview = request
            case .export: exporting = AttachmentFile(request)
            }
        } catch VaultError.notFound {
            errorMessage = String(localized: "item.fileHasntReachedDevice")
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    /// Reads the chosen file (security-scoped, at most 20 Mo) off the main actor, then attaches it.
    private func attach(_ url: URL) async {
        busy = true
        defer { busy = false }
        let max = VaultSession.attachmentMaxBytes
        let read: Result<(Data, String), AttachmentReadError> = await Task.detached {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentTypeKey])
            guard (values?.fileSize ?? 0) <= max else { return .failure(.tooLarge) }
            guard let data = try? Data(contentsOf: url, options: [.uncached]) else { return .failure(.unreadable) }
            guard data.count <= max else { return .failure(.tooLarge) }
            let type = values?.contentType ?? UTType(filenameExtension: url.pathExtension)
            return .success((data, type?.preferredMIMEType ?? "application/octet-stream"))
        }.value
        switch read {
        case .failure(let e):
            errorMessage = e.message
        case .success(var (data, mime)):
            defer { VaultSession.wipeImportBuffer(&data) }
            do {
                let updated = try await session.addAttachment(
                    itemID: item.id, vaultID: item.vaultId, name: url.lastPathComponent, mime: mime, data: data)
                onUpdate(updated)
                model.showToast(String(localized: "item.fileAdded \(url.lastPathComponent)"))
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }

    private func remove(_ attachment: FfiAttachment) async {
        busy = true
        defer { busy = false }
        do {
            let updated = try await session.removeAttachment(
                itemID: item.id, vaultID: item.vaultId, attachmentID: attachment.id)
            onUpdate(updated)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }
}

private enum AttachmentReadError: Error {
    case tooLarge, unreadable

    var message: String {
        switch self {
        case .tooLarge: String(localized: "item.fileOver20Mb")
        case .unreadable: String(localized: "app.cantReadFile")
        }
    }
}

/// A decrypted attachment shown in the preview sheet. Its bytes go with the sheet.
struct AttachmentPreviewRequest: Identifiable {
    let attachment: FfiAttachment
    let data: Data
    var id: String { attachment.id }

    var type: UTType {
        UTType(mimeType: attachment.mime)
            ?? UTType(filenameExtension: (attachment.name as NSString).pathExtension) ?? .data
    }
}

/// The bytes handed to the system's save panel ("Exporter…").
struct AttachmentFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data
    let name: String
    let type: UTType

    init(_ request: AttachmentPreviewRequest) {
        data = request.data
        name = request.attachment.name
        type = request.type
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
        name = ""
        type = .data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

/// In-app preview, kept quiet: the document full bleed, a round glass button to close it at the top,
/// and one glass capsule at the bottom with the file name, the page and "Exporter…" (Liquid Glass on
/// iOS and macOS). A PDF scrolls page after page in PDFKit, an image fits the sheet, any other type
/// says it has no preview.
struct AttachmentPreviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    let request: AttachmentPreviewRequest
    let export: () -> Void

    @State private var page = 1
    @State private var pages = 0
    /// Built once from the bytes: a PDF, or nil for any other type.
    @State private var document: PDFDocument?

    init(request: AttachmentPreviewRequest, export: @escaping () -> Void) {
        self.request = request
        self.export = export
        _document = State(initialValue: request.type.conforms(to: .pdf) ? PDFDocument(data: request.data) : nil)
    }

    var body: some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Self.backdrop)
            .overlay(alignment: .topLeading) { closeButton.padding(Theme.Space.l) }
            .overlay(alignment: .bottom) { capsule.padding(.bottom, Theme.Space.l) }
            // Paper is white: the reader stays light, like a page on a desk, whatever the app's look.
            .environment(\.colorScheme, .light)
            #if os(macOS)
            .frame(minWidth: 520, idealWidth: 640, minHeight: 420, idealHeight: 640)
            #else
            .presentationDragIndicator(.hidden)
            #endif
    }

    @ViewBuilder private var content: some View {
        if let document {
            PDFDocumentView(document: document, page: $page)
                .onAppear { pages = document.pageCount }
                .padding(.top, 58)
                .padding(.horizontal, Theme.Space.m)
                .ignoresSafeArea(edges: .bottom)
                .accessibilityIdentifier("item.attachment.preview.pdf")
        } else if request.type.conforms(to: .image), let image = Self.image(request.data) {
            image
                .resizable()
                .scaledToFit()
                .padding(Theme.Space.xl)
        } else {
            ContentUnavailableView {
                Label(request.attachment.name, systemImage: "doc")
            } description: {
                Text("item.noPreviewForKind")
            }
        }
    }

    private var closeButton: some View {
        Button {
            dismiss()
        } label: {
            Image(systemName: "xmark")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.primary)
                .frame(width: 30, height: 30)
                .glassEffect(.regular.interactive(), in: .circle)
                .contentShape(.circle)
        }
        .buttonStyle(.plain)
        .keyboardShortcut(.cancelAction)
        .accessibilityLabel("Fermer")
        .accessibilityIdentifier("item.attachment.preview.close")
    }

    private var capsule: some View {
        HStack(spacing: Theme.Space.m) {
            Text(request.attachment.name)
                .font(.callout.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 220, alignment: .leading)
            if pages > 1 {
                Text("\(page) / \(pages)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
                    .accessibilityLabel(String(localized: "item.pageOf \(page) \(pages)"))
            }
            Divider().frame(height: 16)
            Button {
                dismiss()
                export()
            } label: {
                Image(systemName: "square.and.arrow.up")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(.primary)
            }
            .buttonStyle(.plain)
            .help("item.export")
            .accessibilityLabel("item.export")
            .accessibilityIdentifier("item.attachment.preview.export")
        }
        .padding(.horizontal, Theme.Space.l)
        .padding(.vertical, Theme.Space.m)
        .glassEffect(.regular, in: .capsule)
        .animation(.snappy, value: page)
    }

    /// The light grey the pages lie on.
    static let backdrop = Color(red: 0.93, green: 0.93, blue: 0.94)

    private static func image(_ data: Data) -> Image? {
        #if os(macOS)
        NSImage(data: data).map { Image(nsImage: $0) }
        #else
        UIImage(data: data).map { Image(uiImage: $0) }
        #endif
    }
}

/// Follows the page shown, for the capsule's "2 / 5".
final class PDFPageTracker: NSObject {
    var onPage: (Int) -> Void = { _ in }

    @objc func pageChanged(_ note: Notification) {
        guard let view = note.object as? PDFView, let current = view.currentPage,
            let index = view.document?.index(for: current)
        else { return }
        onPage(index + 1)
    }
}

/// Pages one under the other, fitted to the width with a margin all around, a soft shadow, on the
/// reader's grey.
private func configure(_ view: PDFView, document: PDFDocument, tracker: PDFPageTracker) {
    view.document = document
    view.displayMode = .singlePageContinuous
    view.displayDirection = .vertical
    view.displaysPageBreaks = true
    view.pageShadowsEnabled = true
    #if os(macOS)
    view.pageBreakMargins = NSEdgeInsets(top: 6, left: 18, bottom: 18, right: 18)
    view.backgroundColor = NSColor(AttachmentPreviewSheet.backdrop)
    #else
    view.pageBreakMargins = UIEdgeInsets(top: 6, left: 10, bottom: 14, right: 10)
    view.backgroundColor = UIColor(AttachmentPreviewSheet.backdrop)
    #endif
    view.autoScales = true
    // The view has no size yet: fit the width again once it is laid out.
    DispatchQueue.main.async {
        view.autoScales = false
        view.autoScales = true
        view.minScaleFactor = view.scaleFactorForSizeToFit
    }
    NotificationCenter.default.addObserver(
        tracker, selector: #selector(PDFPageTracker.pageChanged(_:)), name: .PDFViewPageChanged, object: view)
}

#if os(macOS)
private struct PDFDocumentView: NSViewRepresentable {
    let document: PDFDocument
    @Binding var page: Int

    func makeCoordinator() -> PDFPageTracker { PDFPageTracker() }

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        context.coordinator.onPage = { page = $0 }
        configure(view, document: document, tracker: context.coordinator)
        return view
    }

    func updateNSView(_ view: PDFView, context: Context) {}
}
#else
private struct PDFDocumentView: UIViewRepresentable {
    let document: PDFDocument
    @Binding var page: Int

    func makeCoordinator() -> PDFPageTracker { PDFPageTracker() }

    func makeUIView(context: Context) -> PDFView {
        let view = PDFView()
        context.coordinator.onPage = { page = $0 }
        configure(view, document: document, tracker: context.coordinator)
        return view
    }

    func updateUIView(_ view: PDFView, context: Context) {}
}
#endif
