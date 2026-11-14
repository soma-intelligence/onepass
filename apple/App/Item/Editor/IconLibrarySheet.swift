import DesignKit
import ImageIO
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// "Choisir une icône…" (spec 2026-11-14 part D): three tabs.
///
/// - Logos: the installed icon pack searched by brand name or domain (`IconPack.search`); with no
///   query, what the item's address or title finds. The pack's WebP bytes are stored as they are:
///   a one color mark (black on transparent) is drawn in the text color by `ItemIcon`, so it reads
///   in dark mode too.
/// - Icônes: a house icon (`HouseIcons`) on a tile of one of the 12 palette colors, rendered to a
///   256 px PNG with the light palette (the same picture on every device and appearance).
/// - Image: a photo (PhotosPicker on iOS, a file on the Mac), a centered square of 256 px encoded
///   as PNG from the pixels alone (no EXIF, no GPS). Over 64 KB it is refused.
///
/// `onPick` gets the bytes and their type; the editor applies them on save.
struct IconLibrarySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// The item's title and registrable domain: what the Logos tab shows before a query.
    let title: String
    let domain: String?
    let onPick: (_ mime: String, _ bytes: Data) -> Void

    enum Tab: Hashable { case logos, icons, image }

    @State private var tab: Tab
    @State private var query: String
    @State private var results: [IconPack.Entry] = []
    @State private var colorIndex = 0
    @State private var imageProblem: LocalizedStringKey?
    @State private var choosingFile = false
    #if os(iOS)
    @State private var photo: PhotosPickerItem?
    #endif

    init(
        title: String, domain: String?, initialTab: Tab = .logos, initialQuery: String = "",
        onPick: @escaping (_ mime: String, _ bytes: Data) -> Void
    ) {
        self.title = title
        self.domain = domain
        self.onPick = onPick
        _tab = State(initialValue: initialTab)
        _query = State(initialValue: initialQuery)
    }

    /// The core's cap on a chosen icon.
    static let maxBytes = 65_536

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("iconLibrary.title", selection: $tab) {
                    Text("iconLibrary.tab.logos").tag(Tab.logos)
                    Text("iconLibrary.tab.icons").tag(Tab.icons)
                    Text("iconLibrary.tab.image").tag(Tab.image)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, Theme.Space.l)
                .padding(.vertical, Theme.Space.m)
                .accessibilityIdentifier("iconLibrary.tabs")
                switch tab {
                case .logos: logos
                case .icons: icons
                case .image: image
                }
            }
            .navigationTitle(Text("iconLibrary.title"))
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                        .accessibilityIdentifier("iconLibrary.cancel")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 520, idealWidth: 560, minHeight: 560, idealHeight: 620)
        #else
        .presentationDetents([.large])
        #endif
    }

    private func pick(_ mime: String, _ bytes: Data) {
        onPick(mime, bytes)
        dismiss()
    }

    // MARK: - Logos

    private var pack: IconPack? { model.iconLoader.pack?.pack() }

    /// No query: the item's domain (its first label), else its title.
    private var suggestion: String {
        if let domain, let label = domain.split(separator: ".").first, !label.isEmpty { return String(label) }
        return title
    }

    private var effectiveQuery: String {
        let typed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return typed.isEmpty ? suggestion : typed
    }

    private var logos: some View {
        VStack(spacing: 0) {
            HStack(spacing: Theme.Space.s) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("iconLibrary.search", text: $query)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .accessibilityIdentifier("iconLibrary.search")
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(Text("iconLibrary.clearSearch"))
                }
            }
            .padding(.horizontal, Theme.Space.m)
            .padding(.vertical, Theme.Space.s)
            .background(.fill.tertiary, in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .padding(.horizontal, Theme.Space.l)
            .padding(.bottom, Theme.Space.m)
            ScrollView {
                if results.isEmpty {
                    Text("iconLibrary.noResults")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.top, Theme.Space.xl)
                        .accessibilityIdentifier("iconLibrary.noResults")
                } else {
                    LazyVGrid(columns: Self.columns, spacing: Theme.Space.l) {
                        ForEach(Array(results.enumerated()), id: \.element.icon) { index, entry in
                            logoCell(entry, index: index)
                        }
                    }
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.bottom, Theme.Space.xl)
                }
            }
        }
        .task(id: effectiveQuery) {
            let text = effectiveQuery
            // Typing: wait for a pause. The first search builds the pack's index (off the main actor).
            if !query.isEmpty { try? await Task.sleep(for: .milliseconds(150)) }
            guard !Task.isCancelled, let pack else {
                results = []
                return
            }
            let found = await Task.detached(priority: .userInitiated) { pack.search(text, limit: 60) }.value
            guard !Task.isCancelled else { return }
            results = found
        }
    }

    private static let columns = [GridItem(.adaptive(minimum: 76, maximum: 96), spacing: Theme.Space.m)]

    private func logoCell(_ entry: IconPack.Entry, index: Int) -> some View {
        let data = pack?.icon(number: entry.icon)?.data
        return Button {
            guard let data, data.count <= Self.maxBytes else { return }
            pick("image/webp", data)
        } label: {
            VStack(spacing: Theme.Space.xs) {
                ItemIcon(type: .login, title: entry.name, siteIcon: data, size: 52)
                Text(verbatim: entry.domain ?? entry.name)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .frame(maxWidth: .infinity)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: entry.domain.map { "\(entry.name), \($0)" } ?? entry.name))
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("iconLibrary.logo.\(index)")
    }

    // MARK: - Icônes

    private var tileColor: Color { MonogramStyle.palette[colorIndex].light }

    private var icons: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Space.l) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: Theme.Space.m) {
                        ForEach(MonogramStyle.palette.indices, id: \.self) { index in
                            colorSwatch(index)
                        }
                    }
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.vertical, Theme.Space.xs)
                }
                LazyVGrid(columns: Self.columns, spacing: Theme.Space.l) {
                    ForEach(HouseIcons.all) { icon in
                        houseCell(icon)
                    }
                }
                .padding(.horizontal, Theme.Space.l)
            }
            .padding(.bottom, Theme.Space.xl)
        }
    }

    private func colorSwatch(_ index: Int) -> some View {
        let selected = index == colorIndex
        return Button { colorIndex = index } label: {
            Circle()
                .fill(MonogramStyle.palette[index].light)
                .frame(width: 30, height: 30)
                .padding(3)
                .overlay { Circle().strokeBorder(selected ? Color.primary : .clear, lineWidth: 2) }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text("iconLibrary.color \(index + 1)"))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityIdentifier("iconLibrary.color.\(index)")
    }

    private func houseCell(_ icon: HouseIcon) -> some View {
        Button {
            let png = HouseIcons.render(icon, colorIndex: colorIndex, scheme: .light)
            guard !png.isEmpty, png.count <= Self.maxBytes else { return }
            pick("image/png", png)
        } label: {
            VStack(spacing: Theme.Space.xs) {
                RoundedRectangle(cornerRadius: 52 * 9 / 38, style: .continuous)
                    .fill(tileColor)
                    .frame(width: 52, height: 52)
                    .overlay {
                        Image(systemName: icon.symbol)
                            .resizable()
                            .scaledToFit()
                            .foregroundStyle(.white)
                            .frame(width: 52 * 0.55, height: 52 * 0.55)
                    }
                Text(icon.label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(icon.label))
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("iconLibrary.house.\(icon.id)")
    }

    // MARK: - Image

    private var image: some View {
        VStack(spacing: Theme.Space.l) {
            Image(systemName: "photo.on.rectangle")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
                .padding(.top, Theme.Space.xl)
            Text("iconLibrary.image.hint")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Theme.Space.xl)
            #if os(iOS)
            PhotosPicker(selection: $photo, matching: .images) {
                Text("iconLibrary.image.choose")
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("iconLibrary.image.choose")
            #else
            Button("iconLibrary.image.choose") { choosingFile = true }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("iconLibrary.image.choose")
            #endif
            if let imageProblem {
                Label(imageProblem, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, Theme.Space.xl)
                    .accessibilityIdentifier("iconLibrary.image.problem")
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.png, .jpeg, .heic]) { result in
            guard case .success(let url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            if let data = try? Data(contentsOf: url) { use(data) } else { imageProblem = "iconLibrary.image.unreadable" }
        }
        #if os(iOS)
        .onChange(of: photo) {
            guard let photo else { return }
            Task {
                if let data = try? await photo.loadTransferable(type: Data.self) {
                    use(data)
                } else {
                    imageProblem = "iconLibrary.image.unreadable"
                }
                self.photo = nil
            }
        }
        #endif
    }

    private func use(_ data: Data) {
        guard let png = CustomIconImage.png(from: data) else {
            imageProblem = "iconLibrary.image.unreadable"
            return
        }
        guard png.count <= Self.maxBytes else {
            imageProblem = "iconLibrary.image.tooLarge"
            return
        }
        imageProblem = nil
        pick("image/png", png)
    }
}

/// Turns any image into a chosen icon: a centered square of 256 px, as a PNG written from the
/// pixels alone (EXIF, GPS and other metadata stay behind), transparency kept.
enum CustomIconImage {
    static let side = 256

    static func png(from data: Data) -> Data? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: side * 3,
            ] as CFDictionary)
        else { return nil }
        let edge = min(image.width, image.height)
        let crop = CGRect(x: (image.width - edge) / 2, y: (image.height - edge) / 2, width: edge, height: edge)
        guard edge > 0, let square = image.cropping(to: crop),
            let space = CGColorSpace(name: CGColorSpace.sRGB),
            let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return nil }
        context.interpolationQuality = .high
        context.draw(square, in: CGRect(x: 0, y: 0, width: side, height: side))
        guard let scaled = context.makeImage() else { return nil }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(destination, scaled, nil)
        return CGImageDestinationFinalize(destination) ? out as Data : nil
    }
}
