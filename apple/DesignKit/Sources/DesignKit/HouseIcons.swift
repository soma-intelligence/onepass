import Foundation
import SwiftUI

#if canImport(ImageIO)
    import ImageIO
    import UniformTypeIdentifiers
#endif

/// One "house" icon: an SF Symbol drawn on a colored tile, for things that have no brand logo.
public struct HouseIcon: Identifiable, Sendable {
    public let id: String
    public let symbol: String
    public let label: LocalizedStringResource

    init(_ id: String, _ symbol: String, _ label: String.LocalizationValue) {
        self.id = id
        self.symbol = symbol
        self.label = LocalizedStringResource(label, bundle: .atURL(Bundle.module.bundleURL))
    }
}

public enum HouseIcons {
    /// Side of a rendered icon, in pixels.
    public static let pixelSize = 256

    public static let all: [HouseIcon] = [
        HouseIcon("bank", "building.columns.fill", "houseIcon.bank"),
        HouseIcon("shop", "bag.fill", "houseIcon.shop"),
        HouseIcon("mail", "envelope.fill", "houseIcon.mail"),
        HouseIcon("router", "wifi.router.fill", "houseIcon.router"),
        HouseIcon("wifi", "wifi", "houseIcon.wifi"),
        HouseIcon("school", "graduationcap.fill", "houseIcon.school"),
        HouseIcon("health", "cross.case.fill", "houseIcon.health"),
        HouseIcon("pharmacy", "pills.fill", "houseIcon.pharmacy"),
        HouseIcon("insurance", "umbrella.fill", "houseIcon.insurance"),
        HouseIcon("tax", "percent", "houseIcon.tax"),
        HouseIcon("cityhall", "building.2.fill", "houseIcon.cityhall"),
        HouseIcon("work", "briefcase.fill", "houseIcon.work"),
        HouseIcon("game", "gamecontroller.fill", "houseIcon.game"),
        HouseIcon("music", "music.note", "houseIcon.music"),
        HouseIcon("video", "play.rectangle.fill", "houseIcon.video"),
        HouseIcon("cloud", "cloud.fill", "houseIcon.cloud"),
        HouseIcon("server", "server.rack", "houseIcon.server"),
        HouseIcon("database", "cylinder.split.1x2.fill", "houseIcon.database"),
        HouseIcon("key", "key.fill", "houseIcon.key"),
        HouseIcon("home", "house.fill", "houseIcon.home"),
        HouseIcon("car", "car.fill", "houseIcon.car"),
        HouseIcon("travel", "airplane", "houseIcon.travel"),
        HouseIcon("sport", "figure.run", "houseIcon.sport"),
        HouseIcon("crypto", "bitcoinsign.circle.fill", "houseIcon.crypto"),
        HouseIcon("phone", "phone.fill", "houseIcon.phone"),
        HouseIcon("energy", "bolt.fill", "houseIcon.energy"),
        HouseIcon("water", "drop.fill", "houseIcon.water"),
        HouseIcon("transport", "tram.fill", "houseIcon.transport"),
        HouseIcon("food", "fork.knife", "houseIcon.food"),
        HouseIcon("delivery", "shippingbox.fill", "houseIcon.delivery"),
        HouseIcon("social", "bubble.left.and.bubble.right.fill", "houseIcon.social"),
        HouseIcon("news", "newspaper.fill", "houseIcon.news"),
        HouseIcon("photo", "photo.fill", "houseIcon.photo"),
        HouseIcon("code", "chevron.left.forwardslash.chevron.right", "houseIcon.code"),
        HouseIcon("printer", "printer.fill", "houseIcon.printer"),
        HouseIcon("camera", "camera.fill", "houseIcon.camera"),
        HouseIcon("lock", "lock.fill", "houseIcon.lock"),
        HouseIcon("gift", "gift.fill", "houseIcon.gift"),
        HouseIcon("charity", "heart.fill", "houseIcon.charity"),
        HouseIcon("government", "flag.fill", "houseIcon.government"),
    ]

    /// A 256 x 256 px PNG (scale 1, sRGB, transparent outside the tile) of the icon: the palette
    /// tile at `colorIndex` (wrapped modulo 12) with a white symbol at 55% of the tile.
    @MainActor
    public static func render(_ icon: HouseIcon, colorIndex: Int, scheme: ColorScheme) -> Data {
        let count = MonogramStyle.paletteRGB.count
        let pair = MonogramStyle.paletteRGB[((colorIndex % count) + count) % count]
        let rgb = scheme == .dark ? pair.dark : pair.light
        let side = CGFloat(pixelSize)
        let tile = Color(.sRGB, red: Double(rgb.red) / 255, green: Double(rgb.green) / 255, blue: Double(rgb.blue) / 255, opacity: 1)
        let content = ZStack {
            RoundedRectangle(cornerRadius: side * 9 / 38, style: .continuous).fill(tile)
            Image(systemName: icon.symbol)
                .resizable()
                .scaledToFit()
                .foregroundStyle(Color.white)
                .frame(width: side * 0.55, height: side * 0.55)
        }
        .frame(width: side, height: side)
        .environment(\.colorScheme, scheme)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 1
        renderer.proposedSize = ProposedViewSize(width: side, height: side)
        guard let image = renderer.cgImage else { return Data() }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil) else { return Data() }
        CGImageDestinationAddImage(dest, image, nil)
        guard CGImageDestinationFinalize(dest) else { return Data() }
        return out as Data
    }
}
