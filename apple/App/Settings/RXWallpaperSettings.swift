#if os(iOS)
import DesignKit
import OSLog
import PhotosUI
import SwiftUI
import UIKit

/// The wallpaper behind the Accueil hero: the default art (light or dark with the appearance), one
/// of the bundled themes (`Assets.xcassets/Wallpapers`, made by penpot-lab/wallpapers/generate.py),
/// or a photo the user imported. The choice is one string in the browse defaults.
@MainActor
enum RXWallpaper {
    static let storageKey = "rx.home.wallpaper"
    /// The default art, which follows the appearance.
    static let automatic = "auto"
    /// The imported photo, stored in Application Support.
    static let uploaded = "upload"
    private static let uploadLightKey = "rx.home.wallpaper.uploadLight"

    /// A theme of the picker: its chip title and its pictures.
    struct Category: Identifiable, Hashable {
        let id: String
        let count: Int

        /// An interpolated literal would look up "rx.wallpaper.category.%@": the key is a plain String.
        var title: LocalizedStringKey { LocalizedStringKey("rx.wallpaper.category." + id) }
        var names: [String] { (1...count).map { "wp-\(id)-\($0)" } }
    }

    /// The picker's themes, in chip order.
    static let categories: [Category] = [
        "glass", "silk", "metal", "lights", "lava", "velvet", "horizon", "particles",
    ].map { Category(id: $0, count: 6) }

    /// Bundled wallpapers whose top half is light, so the hero keeps dark words over them
    /// (generate.py's manifest, `isLight`).
    static let lightNames: Set<String> = [
        "wp-metal-2", "wp-metal-3", "wp-velvet-1", "wp-velvet-2", "wp-velvet-3", "wp-glass-1", "wp-glass-2", "wp-glass-3", "wp-glass-4", "wp-glass-5", "wp-glass-6",
    ]

    /// What the hero shows for the stored choice: the picture, and whether its words go dark.
    struct Resolved {
        let image: Image
        let isLight: Bool
    }

    static func resolve(_ id: String, colorScheme: ColorScheme) -> Resolved {
        #if DEBUG
        // Captures: `-OnePassDemoWallpaper <name>` shows that wallpaper whatever is stored.
        let id = UserDefaults.standard.string(forKey: "OnePassDemoWallpaper") ?? id
        #endif
        if id == uploaded, let photo = UploadCache.image() {
            return Resolved(image: Image(uiImage: photo), isLight: AppModel.browseDefaults.bool(forKey: uploadLightKey))
        }
        if id.hasPrefix("wp-"), UIImage(named: id) != nil {
            return Resolved(image: Image(id), isLight: lightNames.contains(id))
        }
        let light = colorScheme == .light
        return Resolved(image: Image(light ? RXHero.item : RXHero.home), isLight: light)
    }

    static func thumbnail(_ name: String) -> String { name + "-thumb" }

    // MARK: Imported photo

    static var uploadURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Wallpaper", isDirectory: true).appendingPathComponent("home.jpg")
    }

    static var hasUpload: Bool { FileManager.default.fileExists(atPath: uploadURL.path) }

    /// Scales the photo to the hero's width, stores it as JPEG and records whether it is light.
    static func storeUpload(_ data: Data) throws {
        guard let source = UIImage(data: data) else { throw CocoaError(.fileReadCorruptFile) }
        let width: CGFloat = 1179
        let scale = min(1, width / max(source.size.width, 1))
        let size = CGSize(width: (source.size.width * scale).rounded(), height: (source.size.height * scale).rounded())
        let format = UIGraphicsImageRendererFormat.default()
        format.scale = 1
        let image = UIGraphicsImageRenderer(size: size, format: format).image { _ in
            source.draw(in: CGRect(origin: .zero, size: size))
        }
        guard let jpeg = image.jpegData(compressionQuality: 0.85) else { throw CocoaError(.fileWriteUnknown) }
        try FileManager.default.createDirectory(at: uploadURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try jpeg.write(to: uploadURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        AppModel.browseDefaults.set(topHalfIsLight(image), forKey: uploadLightKey)
        UploadCache.reset()
    }

    /// Mean luminance of the top half above 0.55: dark words read better there.
    private static func topHalfIsLight(_ image: UIImage) -> Bool {
        guard let cg = image.cgImage else { return false }
        let side = 24
        var pixels = [UInt8](repeating: 0, count: side * side * 4)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(
                data: buffer.baseAddress, width: side, height: side, bitsPerComponent: 8, bytesPerRow: side * 4,
                space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            ) else { return false }
            context.draw(cg, in: CGRect(x: 0, y: 0, width: side, height: side))
            return true
        }
        guard drawn else { return false }
        // CGContext rows run bottom-up: the first half of the buffer is the top of the picture.
        var total = 0.0
        for index in stride(from: 0, to: pixels.count / 2, by: 4) {
            total += 0.2126 * Double(pixels[index]) + 0.7152 * Double(pixels[index + 1]) + 0.0722 * Double(pixels[index + 2])
        }
        return total / Double(side * side / 2) / 255 > 0.55
    }

    /// The imported photo, decoded once per stored file.
    @MainActor
    enum UploadCache {
        private static var cached: UIImage?

        static func image() -> UIImage? {
            if let cached { return cached }
            cached = UIImage(contentsOfFile: uploadURL.path)
            return cached
        }

        static func reset() { cached = nil }
    }
}

/// Réglages > Général: the wallpaper of Accueil, one row that opens the picker.
struct WallpaperSection: View {
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var selection = RXWallpaper.automatic
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    /// Captures: `-OnePassDemoWallpaperPicker YES` opens the picker. Debug builds only.
    @State private var picking: Bool = {
        #if DEBUG
        UserDefaults.standard.bool(forKey: "OnePassDemoWallpaperPicker")
        #else
        false
        #endif
    }()
    @Environment(\.colorScheme) private var colorScheme

    /// The RX look only: the classic Accueil has no hero to dress.
    var body: some View {
        if rxDesign { section }
    }

    private var section: some View {
        Section {
            Button {
                picking = true
            } label: {
                HStack(spacing: Theme.Space.m) {
                    RXWallpaper.resolve(selection, colorScheme: colorScheme).image
                        .resizable()
                        .scaledToFill()
                        .frame(width: 44, height: 64)
                        .clipShape(.rect(cornerRadius: 10, style: .continuous))
                        .accessibilityHidden(true)
                    Text("rx.wallpaper.title")
                        .foregroundStyle(.primary)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("settings.wallpaper")
        }
        .sheet(isPresented: $picking) {
            RXWallpaperPicker()
                .presentationDetents([.large])
        }
    }
}

/// The wallpaper picker: one chip per theme, a grid of its pictures; a tap applies at once.
/// Import takes a photo from the library (no access to the whole library: the system picker).
struct RXWallpaperPicker: View {
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var selection = RXWallpaper.automatic
    @Environment(\.dismiss) private var dismiss
    @State private var category: String
    @State private var photoItem: PhotosPickerItem?
    @State private var hasUpload = RXWallpaper.hasUpload
    @State private var importFailed = false

    private typealias RX = Theme.RX
    private static let defaultChip = "default"
    private static let uploadedChip = "uploaded"
    private let columns = Array(repeating: GridItem(.flexible(), spacing: Theme.RX.Space.m), count: 3)

    init() {
        let stored = AppModel.browseDefaults.string(forKey: RXWallpaper.storageKey) ?? RXWallpaper.automatic
        let owner = RXWallpaper.categories.first { $0.names.contains(stored) }
        var initial = owner?.id ?? (stored == RXWallpaper.uploaded ? Self.uploadedChip : Self.defaultChip)
        #if DEBUG
        if let demo = UserDefaults.standard.string(forKey: "OnePassDemoWallpaperChip") { initial = demo }
        #endif
        _category = State(initialValue: initial)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                chips
                ScrollView {
                    LazyVGrid(columns: columns, spacing: RX.Space.m) {
                        tiles
                    }
                    .padding(.horizontal, RX.Space.gutter)
                    .padding(.vertical, RX.Space.l)
                }
            }
            .background(RX.Palette.pageBackground.color)
            .navigationTitle(Text("rx.wallpaper.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { dismiss() }
                        .accessibilityIdentifier("rx.wallpaper.close")
                }
                ToolbarItem(placement: .primaryAction) {
                    PhotosPicker(selection: $photoItem, matching: .images) {
                        Text("rx.wallpaper.upload")
                    }
                    .accessibilityIdentifier("rx.wallpaper.upload")
                }
            }
            .onChange(of: photoItem) { _, item in
                guard let item else { return }
                Task { await importPhoto(item) }
            }
            .alert(Text("rx.wallpaper.importFailed"), isPresented: $importFailed) {
                Button("OK", role: .cancel) {}
            }
            .sensoryFeedback(.selection, trigger: selection)
        }
    }

    private var chipIDs: [String] {
        [Self.defaultChip] + (hasUpload ? [Self.uploadedChip] : []) + RXWallpaper.categories.map(\.id)
    }

    private func chipTitle(_ id: String) -> Text {
        switch id {
        case Self.defaultChip: Text("rx.wallpaper.default")
        case Self.uploadedChip: Text("rx.wallpaper.uploaded")
        default: Text(LocalizedStringKey("rx.wallpaper.category." + id))
        }
    }

    private var chips: some View {
        ScrollViewReader { proxy in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: RX.Space.s) {
                    ForEach(chipIDs, id: \.self) { id in
                        Button {
                            withAnimation(.snappy) { category = id }
                        } label: {
                            RXChip(chipTitle(id), selected: category == id)
                        }
                        .buttonStyle(.plain)
                        .id(id)
                        .accessibilityIdentifier("rx.wallpaper.chip.\(id)")
                    }
                }
                .padding(.horizontal, RX.Space.gutter)
                .padding(.vertical, RX.Space.s)
            }
            .onAppear { proxy.scrollTo(category, anchor: .center) }
            .onChange(of: category) { _, id in
                withAnimation(.snappy) { proxy.scrollTo(id, anchor: .center) }
            }
        }
    }

    @ViewBuilder private var tiles: some View {
        switch category {
        case Self.defaultChip:
            tile(id: RXWallpaper.automatic, image: Image(RXHero.home), badge: "circle.lefthalf.filled")
        case Self.uploadedChip:
            if let photo = RXWallpaper.UploadCache.image() {
                tile(id: RXWallpaper.uploaded, image: Image(uiImage: photo), badge: nil)
            }
        default:
            if let theme = RXWallpaper.categories.first(where: { $0.id == category }) {
                ForEach(theme.names, id: \.self) { name in
                    tile(id: name, image: Image(RXWallpaper.thumbnail(name)), badge: nil)
                }
            }
        }
    }

    private func tile(id: String, image: Image, badge: String?) -> some View {
        let selected = selection == id
        return Button {
            selection = id
        } label: {
            Color.clear
                .aspectRatio(0.66, contentMode: .fit)
                .overlay {
                    image
                        .resizable()
                        .scaledToFill()
                }
                .clipShape(.rect(cornerRadius: RX.Radius.card, style: .continuous))
                .overlay(alignment: .bottomTrailing) {
                    if let badge {
                        Image(systemName: badge)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.white)
                            .shadow(color: .black.opacity(0.35), radius: 3)
                            .padding(RX.Space.s)
                            .accessibilityHidden(true)
                    }
                }
                .overlay {
                    RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous)
                        .strokeBorder(selected ? RX.Palette.accent.color : .clear, lineWidth: 3)
                }
                .overlay(alignment: .topTrailing) {
                    if selected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.title3)
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, RX.Palette.accent.color)
                            .padding(RX.Space.s)
                            .accessibilityHidden(true)
                    }
                }
                .contentShape(.rect(cornerRadius: RX.Radius.card))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text("rx.wallpaper.title"))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("rx.wallpaper.\(id)")
    }

    private func importPhoto(_ item: PhotosPickerItem) async {
        defer { photoItem = nil }
        do {
            guard let data = try await item.loadTransferable(type: Data.self) else { return }
            try RXWallpaper.storeUpload(data)
            hasUpload = true
            category = Self.uploadedChip
            selection = RXWallpaper.uploaded
        } catch {
            Logger(subsystem: "me.somalabs.onepass", category: "wallpaper").error("Import failed: \(error.localizedDescription, privacy: .public)")
            importFailed = true
        }
    }
}
#endif
