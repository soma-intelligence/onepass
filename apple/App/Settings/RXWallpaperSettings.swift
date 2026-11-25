import DesignKit
import OSLog
#if os(iOS)
import PhotosUI
import UIKit
#elseif os(macOS)
import AppKit
#endif
import SwiftUI

#if os(iOS) || os(macOS)
/// The wallpaper behind the Accueil hero: the default art (Soma Brume, which follows the
/// appearance), one of the bundled pictures (`Assets.xcassets/Wallpapers`) or a photo the user
/// imported (iPhone and iPad). The choice is one string in the browse defaults, so every stored
/// name stays valid across releases: "auto", "upload" and "wp-<theme>-<n>[-noir|-clair]".
/// The Mac has no default art nor imported photo: nothing stored, or either of them, is Lava 3.
@MainActor
enum RXWallpaper {
    static let storageKey = "rx.home.wallpaper"
    /// The default art, which follows the appearance. Since 2026-11-25 it is Soma Brume
    /// (`wp-soma-1`): the former near black art (`RXHero.home`) read as too heavy behind the hero.
    static let automatic = "auto"
    /// What the hero shows when nothing is stored: the default art on iPhone and iPad, Lava 3 (a
    /// warm one) on the Mac.
    #if os(macOS)
    static let platformDefault = "wp-lava-3"
    #else
    static let platformDefault = automatic
    #endif
    /// The imported photo, stored in Application Support.
    static let uploaded = "upload"
    private static let uploadLightKey = "rx.home.wallpaper.uploadLight"
    /// Whether the wallpaper drifts (`RXLiveWallpaper`), on Accueil and the lock screen. On by default.
    static let liveKey = "rx.home.wallpaper.live"

    /// The picture behind "auto": the first Soma wallpaper.
    static let automaticArt = "wp-soma-1"

    /// The tones of a theme: its own colours, a low key one and a high key one (generate.py `tone`).
    enum Tone: String, CaseIterable, Identifiable {
        case natural, noir, clair
        var id: String { rawValue }
        var title: LocalizedStringKey { LocalizedStringKey("rx.wallpaper.tone." + rawValue) }
        /// The suffix of the picture's name: "" for its own colours.
        var suffix: String { self == .natural ? "" : "-" + rawValue }

        /// The tone of a stored wallpaper name.
        static func of(_ name: String) -> Tone {
            allCases.first { $0 != .natural && name.hasSuffix($0.suffix) } ?? .natural
        }
    }

    /// The name of the picture without its tone: "wp-lava-3-noir" is "wp-lava-3".
    static func baseName(_ name: String) -> String {
        let tone = Tone.of(name)
        return tone == .natural ? name : String(name.dropLast(tone.suffix.count))
    }

    /// A theme of the picker: its chip title and its pictures.
    struct Category: Identifiable, Hashable {
        let id: String
        let count: Int
        /// Lava, Lights, Silk, Glass and Landscape also come in Noir and Clair.
        var hasTones: Bool { ["lava", "lights", "silk", "glass", "landscape"].contains(id) }
        /// Soma pictures carry a light and a dark image in one asset: they follow the appearance
        /// on their own, so they need no tone and their words follow the appearance too.
        var followsAppearance: Bool { id == "soma" }

        /// An interpolated literal would look up "rx.wallpaper.category.%@": the key is a plain String.
        var title: LocalizedStringKey { LocalizedStringKey("rx.wallpaper.category." + id) }
        var names: [String] { (1...count).map { "wp-\(id)-\($0)" } }
    }

    /// The groups of the iPhone picker, in segment order. Soma first: calm, made for the hero.
    enum Group: String, CaseIterable, Identifiable {
        case soma, gradients, photos, mine
        var id: String { rawValue }
        var title: LocalizedStringKey { LocalizedStringKey("rx.wallpaper.group." + rawValue) }
    }

    static let soma = Category(id: "soma", count: 6)
    /// Drawn themes, grouped as "Dégradés" on iPhone.
    static let gradientThemes: [Category] = [
        "silk", "lava", "glass", "lights", "horizon", "velvet", "metal", "particles",
    ].map { Category(id: $0, count: 6) }
    /// Photographs, grouped as "Photos" on iPhone.
    static let photoThemes: [Category] = [Category(id: "landscape", count: 6)]

    /// Every theme, in chip order on the Mac.
    static let categories: [Category] = [soma] + gradientThemes + photoThemes

    /// The group a stored name belongs to, so the picker opens where the choice is.
    static func group(of name: String) -> Group {
        if name == automatic || name.hasPrefix("wp-soma-") { return .soma }
        if name == uploaded { return .mine }
        let base = baseName(name)
        if photoThemes.contains(where: { $0.names.contains(base) }) { return .photos }
        if gradientThemes.contains(where: { $0.names.contains(base) }) { return .gradients }
        return .soma
    }

    /// Bundled wallpapers whose top half is light, so the hero keeps dark words over them
    /// (generate.py's manifest, `isLight`).
    static let lightNames: Set<String> = [
        "wp-metal-2", "wp-metal-3", "wp-velvet-1", "wp-velvet-2", "wp-velvet-3", "wp-glass-1", "wp-glass-2", "wp-glass-3", "wp-glass-4", "wp-glass-5", "wp-glass-6",
        "wp-landscape-1", "wp-landscape-3", "wp-landscape-5", "wp-landscape-1-noir", "wp-landscape-3-noir",
    ]

    /// What the hero shows for the stored choice: the picture, and whether its words go dark.
    struct Resolved {
        let image: Image
        let isLight: Bool
        /// Drawn pictures flow (`RXLiveWallpaper`); photos (Landscape, an imported one) only get
        /// the slow camera move, so trees and faces never wobble.
        var flows = true
    }

    static func resolve(_ id: String, colorScheme: ColorScheme) -> Resolved {
        #if DEBUG
        // Captures: `-OnePassDemoWallpaper <name>` shows that wallpaper whatever is stored.
        let id = UserDefaults.standard.string(forKey: "OnePassDemoWallpaper") ?? id
        #endif
        #if os(iOS)
        if id == uploaded, let photo = UploadCache.image() {
            return Resolved(image: Image(uiImage: photo), isLight: AppModel.browseDefaults.bool(forKey: uploadLightKey), flows: false)
        }
        if id == automatic, isBundled(automaticArt) {
            return Resolved(image: Image(automaticArt), isLight: colorScheme == .light)
        }
        #endif
        if id.hasPrefix("wp-"), isBundled(id) {
            // Soma pictures swap with the appearance, so their words do too. A Clair picture is
            // light, a Noir one dark unless its sky stays pale (misty photos).
            let light = if id.hasPrefix("wp-soma-") {
                colorScheme == .light
            } else {
                switch Tone.of(id) {
                case .clair: true
                case .noir, .natural: lightNames.contains(id)
                }
            }
            return Resolved(image: Image(id), isLight: light, flows: !id.hasPrefix("wp-landscape-"))
        }
        #if os(macOS)
        // The default art, an imported photo or a name no longer bundled: the Mac's own default.
        if id != platformDefault { return resolve(platformDefault, colorScheme: colorScheme) }
        #endif
        let light = colorScheme == .light
        return Resolved(image: Image(light ? RXHero.item : RXHero.home), isLight: light)
    }

    static func thumbnail(_ name: String) -> String { name + "-thumb" }

    /// Whether the asset catalog has a picture of that name.
    static func isBundled(_ name: String) -> Bool {
        #if os(macOS)
        NSImage(named: name) != nil
        #else
        UIImage(named: name) != nil
        #endif
    }

    #if os(iOS)
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

    /// Width over height of the window the hero fills, so every preview has the screen's shape.
    /// Clamped: a split iPad window can be almost square, and a tile that wide breaks the grid.
    static var screenRatio: CGFloat {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        let size = scene?.keyWindow?.bounds.size ?? scene?.screen.bounds.size ?? CGSize(width: 402, height: 874)
        let ratio = min(size.width, size.height) / max(max(size.width, size.height), 1)
        return min(max(ratio, 0.42), 0.75)
    }
    #endif
}
#endif

#if os(iOS)

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

    private typealias RX = Theme.RX
    /// The row's thumbnail: a small screen, as tall as two lines of a row.
    private static let thumbHeight: CGFloat = 64

    /// The RX look only: the classic Accueil has no hero to dress.
    var body: some View {
        if rxDesign { section }
    }

    private var section: some View {
        Section {
            Button {
                picking = true
            } label: {
                HStack(spacing: RX.Space.m) {
                    RXWallpaper.resolve(selection, colorScheme: colorScheme).image
                        .resizable()
                        .scaledToFill()
                        .frame(width: Self.thumbHeight * RXWallpaper.screenRatio, height: Self.thumbHeight)
                        .clipShape(.rect(cornerRadius: RX.Space.s, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: RX.Space.s, style: .continuous)
                                .strokeBorder(RX.Palette.separator.color, lineWidth: 0.5)
                        }
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

/// The wallpaper picker. From the top: a live preview of Accueil with the choice, the four groups
/// (Soma, Dégradés, Photos, Tes photos), then the group's pictures as small screens on one card.
/// A tap applies at once; the preview shows it before the sheet closes.
struct RXWallpaperPicker: View {
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var selection = RXWallpaper.automatic
    @AppStorage(RXWallpaper.liveKey, store: AppModel.browseDefaults) private var live = true
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    @State private var group: RXWallpaper.Group
    /// The theme shown in Dégradés.
    @State private var theme: String
    @State private var tone: RXWallpaper.Tone
    @State private var photoItem: PhotosPickerItem?
    @State private var choosingPhoto = false
    @State private var hasUpload = RXWallpaper.hasUpload
    @State private var importFailed = false

    private typealias RX = Theme.RX
    private let ratio = RXWallpaper.screenRatio

    /// The grid sits on a card with `cardPadding` around it, so a tile's corner is the card's
    /// minus that padding: the two curves stay concentric.
    private static let cardPadding = RX.Space.m
    private static var tileRadius: CGFloat { RX.Radius.card - cardPadding }
    /// The selection ring floats this far outside the tile, less than the grid gap, so two rings
    /// never touch and the picture itself is never covered.
    private static let ringGap: CGFloat = 4
    private static let previewHeight: CGFloat = 300

    init() {
        let stored = AppModel.browseDefaults.string(forKey: RXWallpaper.storageKey) ?? RXWallpaper.automatic
        var group = RXWallpaper.group(of: stored)
        let base = RXWallpaper.baseName(stored)
        var theme = RXWallpaper.gradientThemes.first { $0.names.contains(base) }?.id ?? "silk"
        #if DEBUG
        // Captures: `-OnePassDemoWallpaperChip <group or theme>` opens that group or theme.
        if let demo = UserDefaults.standard.string(forKey: "OnePassDemoWallpaperChip") {
            if let picked = RXWallpaper.Group(rawValue: demo) {
                group = picked
            } else if RXWallpaper.gradientThemes.contains(where: { $0.id == demo }) {
                group = .gradients
                theme = demo
            }
        }
        #endif
        _group = State(initialValue: group)
        _theme = State(initialValue: theme)
        _tone = State(initialValue: RXWallpaper.Tone.of(stored))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: RX.Space.xl) {
                    preview
                    VStack(spacing: RX.Space.l) {
                        Picker(selection: $group.animation(.snappy)) {
                            ForEach(RXWallpaper.Group.allCases) { group in
                                Text(group.title).tag(group)
                            }
                        } label: {
                            Text("rx.wallpaper.title")
                        }
                        .pickerStyle(.segmented)
                        .accessibilityIdentifier("rx.wallpaper.group")
                        .padding(.horizontal, RX.Space.gutter)
                        groupContent
                    }
                    liveCard
                        .padding(.horizontal, RX.Space.gutter)
                }
                .padding(.vertical, RX.Space.l)
            }
            .background(RX.Palette.pageBackground.color)
            .navigationTitle(Text("rx.wallpaper.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { dismiss() }
                        .accessibilityIdentifier("rx.wallpaper.close")
                }
            }
            .photosPicker(isPresented: $choosingPhoto, selection: $photoItem, matching: .images)
            .onChange(of: photoItem) { _, item in
                guard let item else { return }
                Task { await importPhoto(item) }
            }
            .alert(Text("rx.wallpaper.importFailed"), isPresented: $importFailed) {
                Button("OK", role: .cancel) {}
            }
            .sensoryFeedback(.selection, trigger: selection)
            // A new tone applies at once to the picture chosen in the theme on screen.
            .onChange(of: tone) { _, tone in
                let base = RXWallpaper.baseName(selection)
                if let shown = toneTheme, shown.names.contains(base) {
                    selection = base + tone.suffix
                }
            }
        }
    }

    // MARK: Preview

    /// Accueil in miniature with the choice: the wallpaper (moving when Fond animé is on), the
    /// greeting in the colour the hero would use over it, and the first card of the list. It
    /// answers "how will it look" before the sheet closes.
    private var preview: some View {
        let resolved = RXWallpaper.resolve(selection, colorScheme: colorScheme)
        let width = Self.previewHeight * ratio
        // A phone's corner is about 14% of its width; the inner card keeps the same centre.
        let radius = width * 0.14
        let inset = RX.Space.s
        let ink: Color = resolved.isLight ? .black.opacity(0.72) : .white.opacity(0.92)
        return ZStack(alignment: .top) {
            resolved.image
                .resizable()
                .scaledToFill()
                .frame(width: width, height: Self.previewHeight)
                .rxLiveWallpaper(active: live, flow: resolved.flows)
                .clipped()
            VStack(spacing: RX.Space.s) {
                Capsule()
                    .fill(.black)
                    .frame(width: width * 0.3, height: RX.Space.s + RX.Space.xs)
                    .padding(.top, RX.Space.s)
                Spacer().frame(height: RX.Space.xl)
                Capsule().fill(ink.opacity(0.7)).frame(width: width * 0.3, height: RX.Space.xs + 1)
                Capsule().fill(ink).frame(width: width * 0.55, height: RX.Space.s + 2)
                HStack(spacing: RX.Space.m) {
                    ForEach(0 ..< 3, id: \.self) { _ in
                        Circle().fill(.ultraThinMaterial).frame(width: RX.Space.l + RX.Space.xs)
                    }
                }
                .padding(.top, RX.Space.s)
                Spacer(minLength: 0)
                UnevenRoundedRectangle(topLeadingRadius: radius - inset, bottomLeadingRadius: radius - inset,
                                       bottomTrailingRadius: radius - inset, topTrailingRadius: radius - inset,
                                       style: .continuous)
                    .fill(RX.Palette.cardBackground.color)
                    .overlay(alignment: .topLeading) {
                        VStack(alignment: .leading, spacing: RX.Space.s) {
                            ForEach(0 ..< 3, id: \.self) { row in
                                HStack(spacing: RX.Space.s) {
                                    Circle().fill(RX.Palette.field.color).frame(width: RX.Space.m)
                                    Capsule().fill(RX.Palette.field.color)
                                        .frame(width: width * (row == 1 ? 0.35 : 0.45), height: RX.Space.xs + 1)
                                }
                            }
                        }
                        .padding(RX.Space.m)
                    }
                    .frame(height: Self.previewHeight * 0.36)
                    .padding(inset)
            }
            .frame(width: width, height: Self.previewHeight)
        }
        .frame(width: width, height: Self.previewHeight)
        .clipShape(.rect(cornerRadius: radius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .strokeBorder(RX.Palette.separator.color, lineWidth: 1)
        }
        .shadow(color: .black.opacity(0.12), radius: RX.Space.l, y: RX.Space.s)
        .animation(.smooth(duration: 0.35), value: selection)
        .frame(maxWidth: .infinity)
        .accessibilityElement()
        .accessibilityLabel(Text("rx.wallpaper.preview"))
        .accessibilityIdentifier("rx.wallpaper.preview")
    }

    // MARK: Groups

    /// The theme whose tone control shows: the Dégradés theme on screen, or Paysage in Photos.
    private var toneTheme: RXWallpaper.Category? {
        switch group {
        case .gradients: RXWallpaper.gradientThemes.first { $0.id == theme && $0.hasTones }
        case .photos: RXWallpaper.photoThemes.first
        case .soma, .mine: nil
        }
    }

    @ViewBuilder private var groupContent: some View {
        switch group {
        case .soma:
            VStack(alignment: .leading, spacing: RX.Space.s) {
                card { somaTiles }
                footer(Text("rx.wallpaper.soma.footer"))
            }
            .padding(.horizontal, RX.Space.gutter)
        case .gradients:
            VStack(spacing: RX.Space.l) {
                themeChips
                VStack(spacing: RX.Space.l) {
                    toneControl
                    card { themeTiles(RXWallpaper.gradientThemes.first { $0.id == theme }) }
                }
                .padding(.horizontal, RX.Space.gutter)
            }
        case .photos:
            VStack(spacing: RX.Space.l) {
                toneControl
                card { themeTiles(RXWallpaper.photoThemes.first) }
            }
            .padding(.horizontal, RX.Space.gutter)
        case .mine:
            VStack(alignment: .leading, spacing: RX.Space.s) {
                card { importTiles }
                footer(Text("rx.wallpaper.import.footer"))
            }
            .padding(.horizontal, RX.Space.gutter)
        }
    }

    /// One card holding a grid of small screens, three across on a phone.
    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 96), spacing: RX.Space.m)], spacing: RX.Space.l) {
            content()
        }
        .padding(Self.cardPadding)
        .background(RX.Palette.cardBackground.color,
                    in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
    }

    private func footer(_ text: Text) -> some View {
        text
            .rxFont(.footnote)
            .foregroundStyle(RX.Palette.textSecondary.color)
            .padding(.horizontal, RX.Space.l)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private var toneControl: some View {
        if toneTheme != nil {
            Picker(selection: $tone) {
                ForEach(RXWallpaper.Tone.allCases) { tone in
                    Text(tone.title).tag(tone)
                }
            } label: {
                Text("rx.wallpaper.tone")
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("rx.wallpaper.tone")
        }
    }

    private var themeChips: some View {
        ScrollViewReader { proxy in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: RX.Space.s) {
                    ForEach(RXWallpaper.gradientThemes) { item in
                        Button {
                            withAnimation(.snappy) { theme = item.id }
                        } label: {
                            RXChip(Text(item.title), selected: theme == item.id)
                        }
                        .buttonStyle(.plain)
                        .id(item.id)
                        .accessibilityIdentifier("rx.wallpaper.chip.\(item.id)")
                    }
                }
                .padding(.horizontal, RX.Space.gutter)
            }
            .onAppear { proxy.scrollTo(theme, anchor: .center) }
            .onChange(of: theme) { _, id in
                withAnimation(.snappy) { proxy.scrollTo(id, anchor: .center) }
            }
        }
    }

    // MARK: Tiles

    /// Soma: the default art (Brume, stored as "auto" as before) then the five others. Each
    /// carries its own light and dark picture, hence no tone control here.
    @ViewBuilder private var somaTiles: some View {
        let selected = selection == RXWallpaper.automaticArt ? RXWallpaper.automatic : selection
        ForEach(Array(RXWallpaper.soma.names.enumerated()), id: \.offset) { index, name in
            let id = index == 0 ? RXWallpaper.automatic : name
            tile(id: id, isSelected: selected == id, image: Image(RXWallpaper.thumbnail(name)),
                 label: Text(LocalizedStringKey("rx.wallpaper.soma.\(index + 1)")), showsCaption: true)
        }
    }

    @ViewBuilder private func themeTiles(_ category: RXWallpaper.Category?) -> some View {
        if let category {
            let suffix = category.hasTones ? tone.suffix : ""
            ForEach(Array(category.names.enumerated()), id: \.offset) { index, base in
                let name = base + suffix
                tile(id: name, isSelected: selection == name, image: Image(RXWallpaper.thumbnail(name)),
                     label: Text(category.title) + Text(verbatim: " \(index + 1)"), showsCaption: false)
            }
        }
    }

    /// Tes photos: the system photo picker (no access to the whole library) as the first tile,
    /// then the photo already imported, if any.
    @ViewBuilder private var importTiles: some View {
        // A button plus `.photosPicker`, not `PhotosPicker { label }`: that label closure is
        // nonisolated and cannot build this main actor tile.
        Button {
            choosingPhoto = true
        } label: {
            VStack(spacing: RX.Space.s) {
                screen {
                    RoundedRectangle(cornerRadius: Self.tileRadius, style: .continuous)
                        .fill(RX.Palette.field.color)
                        .overlay {
                            Image(systemName: "photo.badge.plus")
                                .font(.title2)
                                .foregroundStyle(RX.Palette.accent.color)
                        }
                }
                .overlay {
                    RoundedRectangle(cornerRadius: Self.tileRadius, style: .continuous)
                        .strokeBorder(RX.Palette.separator.color, style: StrokeStyle(lineWidth: 1, dash: [4, 4]))
                }
                Text("rx.wallpaper.upload")
                    .rxFont(.footnote)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .lineLimit(1)
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("rx.wallpaper.upload")
        if hasUpload, let photo = RXWallpaper.UploadCache.image() {
            tile(id: RXWallpaper.uploaded, isSelected: selection == RXWallpaper.uploaded, image: Image(uiImage: photo),
                 label: Text("rx.wallpaper.uploaded"), showsCaption: true)
        }
    }

    /// A small screen: the screen's own shape, the concentric corner.
    private func screen<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        Color.clear
            .aspectRatio(ratio, contentMode: .fit)
            .overlay { content() }
            .clipShape(.rect(cornerRadius: Self.tileRadius, style: .continuous))
    }

    private func tile(id: String, isSelected: Bool, image: Image, label: Text, showsCaption: Bool) -> some View {
        Button {
            selection = id
        } label: {
            VStack(spacing: RX.Space.s) {
                screen {
                    image
                        .resizable()
                        .scaledToFill()
                }
                // A hairline, so a pale picture never melts into the white card.
                .overlay {
                    RoundedRectangle(cornerRadius: Self.tileRadius, style: .continuous)
                        .strokeBorder(RX.Palette.separator.color, lineWidth: 0.5)
                }
                .overlay(alignment: .bottomTrailing) {
                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.title3)
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, RX.Palette.accent.color)
                            .padding(RX.Space.s)
                            .transition(.scale.combined(with: .opacity))
                            .accessibilityHidden(true)
                    }
                }
                // The ring sits outside the picture, its corner the tile's plus the gap.
                .padding(Self.ringGap)
                .overlay {
                    RoundedRectangle(cornerRadius: Self.tileRadius + Self.ringGap, style: .continuous)
                        .strokeBorder(isSelected ? RX.Palette.accent.color : .clear, lineWidth: 2.5)
                }
                .padding(-Self.ringGap)
                if showsCaption {
                    label
                        .rxFont(isSelected ? .footnoteBold : .footnote)
                        .foregroundStyle(isSelected ? RX.Palette.accentText.color : RX.Palette.textPrimary.color)
                        .lineLimit(1)
                }
            }
            .animation(.snappy, value: isSelected)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityIdentifier("rx.wallpaper.\(id)")
    }

    private var liveCard: some View {
        Toggle(isOn: $live) {
            Text("rx.wallpaper.live")
            Text("rx.wallpaper.live.detail")
        }
        .padding(RX.Space.l)
        .background(RX.Palette.cardBackground.color,
                    in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        .accessibilityIdentifier("rx.wallpaper.live")
    }

    private func importPhoto(_ item: PhotosPickerItem) async {
        defer { photoItem = nil }
        do {
            guard let data = try await item.loadTransferable(type: Data.self) else { return }
            try RXWallpaper.storeUpload(data)
            hasUpload = true
            group = .mine
            selection = RXWallpaper.uploaded
        } catch {
            Logger(subsystem: "me.somalabs.onepass", category: "wallpaper").error("Import failed: \(error.localizedDescription, privacy: .public)")
            importFailed = true
        }
    }
}
#endif

#if os(macOS)
/// Réglages > Général on the Mac (the RX popup): the wallpaper of the Accueil hero as one card.
/// The themes as small chips that wrap (Soma first), the tone of the themes that have one, then
/// the theme's pictures as landscape tiles (the hero's shape); a click applies at once.
struct MacWallpaperSection: View {
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var selection = RXWallpaper.platformDefault
    @State private var category: String
    @State private var tone: RXWallpaper.Tone

    private typealias RX = Theme.RX
    private static let tileSize = CGSize(width: 120, height: 68)
    /// The section's rows round at 12 with no inset around the grid: tiles match that corner.
    private static let tileRadius: CGFloat = RX.Space.m
    private static let ringGap: CGFloat = 3

    init() {
        let stored = AppModel.browseDefaults.string(forKey: RXWallpaper.storageKey) ?? RXWallpaper.platformDefault
        let shown = RXWallpaper.isBundled(stored) ? stored : RXWallpaper.platformDefault
        let owner = RXWallpaper.categories.first { $0.names.contains(RXWallpaper.baseName(shown)) }
        _category = State(initialValue: owner?.id ?? "lava")
        _tone = State(initialValue: RXWallpaper.Tone.of(shown))
    }

    var body: some View {
        Section {
            FlowLayout(spacing: RX.Space.s) {
                ForEach(RXWallpaper.categories) { theme in
                    chip(theme)
                }
            }
            if currentTheme?.hasTones == true {
                Picker(selection: $tone) {
                    ForEach(RXWallpaper.Tone.allCases) { tone in
                        Text(tone.title).tag(tone)
                    }
                } label: {
                    Text("rx.wallpaper.tone")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .accessibilityIdentifier("rx.wallpaper.tone")
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: Self.tileSize.width, maximum: 160), spacing: RX.Space.m)],
                      alignment: .leading, spacing: RX.Space.m) {
                if let theme = currentTheme {
                    let suffix = theme.hasTones ? tone.suffix : ""
                    ForEach(theme.names.map { $0 + suffix }, id: \.self) { name in
                        tile(name)
                    }
                }
            }
            .padding(.vertical, RX.Space.xs)
            if currentTheme?.followsAppearance == true {
                Text("rx.wallpaper.soma.footer")
                    .rxFont(.footnote)
                    .foregroundStyle(RX.Palette.textSecondary.color)
            }
        } header: {
            SettingsHeader("rx.wallpaper.title")
        }
        // A new tone applies at once to the picture chosen in this theme.
        .onChange(of: tone) { _, tone in
            let base = RXWallpaper.baseName(selection)
            if let theme = currentTheme, theme.hasTones, theme.names.contains(base) {
                selection = base + tone.suffix
            }
        }
    }

    private var currentTheme: RXWallpaper.Category? {
        RXWallpaper.categories.first { $0.id == category }
    }

    private func chip(_ theme: RXWallpaper.Category) -> some View {
        let selected = category == theme.id
        return Button {
            withAnimation(.snappy) { category = theme.id }
        } label: {
            Text(theme.title)
                .rxFont(.footnoteBold)
                .foregroundStyle(selected ? RX.Palette.onAccent.color : RX.Palette.textPrimary.color)
                .padding(.horizontal, RX.Space.m)
                .frame(height: 28)
                .background(selected ? RX.Palette.accent.color : RX.Palette.field.color, in: Capsule())
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("rx.wallpaper.chip.\(theme.id)")
    }

    private func tile(_ name: String) -> some View {
        let selected = selection == name
        let shape = RoundedRectangle(cornerRadius: Self.tileRadius, style: .continuous)
        return Button {
            selection = name
        } label: {
            Color.clear
                .aspectRatio(Self.tileSize.width / Self.tileSize.height, contentMode: .fit)
                .overlay {
                    Image(RXWallpaper.thumbnail(name))
                        .resizable()
                        .scaledToFill()
                }
                .clipShape(shape)
                .overlay { shape.strokeBorder(RX.Palette.separator.color, lineWidth: 0.5) }
                .overlay(alignment: .bottomTrailing) {
                    if selected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.title3)
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, RX.Palette.accent.color)
                            .padding(RX.Space.xs)
                            .accessibilityHidden(true)
                    }
                }
                // Same ring as on iPhone: outside the picture, concentric with it.
                .padding(Self.ringGap)
                .overlay {
                    RoundedRectangle(cornerRadius: Self.tileRadius + Self.ringGap, style: .continuous)
                        .strokeBorder(selected ? RX.Palette.accent.color : .clear, lineWidth: 2.5)
                }
                .padding(-Self.ringGap)
                .contentShape(shape)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text("rx.wallpaper.title"))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("rx.wallpaper.\(name)")
    }
}
#endif
