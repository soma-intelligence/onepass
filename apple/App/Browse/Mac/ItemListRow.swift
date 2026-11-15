import DesignKit
import SwiftUI
import VaultKit

/// One row of an item list (Mac and iPad list column, iPhone lists): icon (site icon when loaded,
/// otherwise the category tile), title, subtitle, the vault name when the list mixes vaults, and a
/// star on the icon's corner for favorites. Platform neutral: the host list handles selection or navigation.
struct ItemListRow: View {
    @Environment(AppModel.self) private var model
    private let summary: FfiItemSummary
    private let vaultName: String?
    /// The automatic icon the task found (never the chosen one, read from memory at each frame).
    @State private var resolved: ResolvedIcon?

    init(summary: FfiItemSummary, vaultName: String?) {
        self.summary = summary
        self.vaultName = vaultName
    }

    /// A login with no username that signs in with a provider: "Se connecte avec GitHub".
    private var signInLine: String? {
        guard summary.subtitle.isEmpty, let provider = summary.signInProvider else { return nil }
        return String(localized: "browse.signsInWith \(LoginProvider.displayName(provider))")
    }

    private var secondLine: String {
        let line = signInLine ?? summary.listSubtitle
        return line.isEmpty ? ItemCategory.of(summary.itemType).singular : line
    }

    private var taskID: ItemIconTaskID { ItemIconTaskID(summary) }

    /// The row draws the icon the person chose (loaded from the vault): the row's accessibility
    /// value says so, and the icon carries `list.row.icon.custom` (UI tests).
    private var showsCustomIcon: Bool { model.iconLoader.chosenIcon(CustomIconKey(summary)) != nil }

    /// The site icon tile: 36 pt on iPhone and iPad, 40 pt on the Mac.
    #if os(iOS)
    static let iconSize: CGFloat = 36
    #else
    static let iconSize: CGFloat = 40
    #endif
    /// Gap between the icon and the title.
    static let iconSpacing: CGFloat = 12

    var body: some View {
        HStack(spacing: Self.iconSpacing) {
            ItemIcon(type: summary.itemType, title: summary.title, siteIcon: model.iconLoader.shownIcon(taskID, resolved: resolved), size: Self.iconSize, brand: summary.cardBrand,
                useCategory: summary.usesCategoryIcon, tint: ItemTint.color(named: summary.color),
                domain: ItemIconResolver.registrableDomain(summary.primaryUrl))
                .accessibilityIdentifier(showsCustomIcon ? "list.row.icon.custom" : "")
                .favoriteBadge(summary.favorite, iconSize: Self.iconSize)
            VStack(alignment: .leading, spacing: 1) {
                Text(summary.title)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                Text(secondLine)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            // Travel Mode per item (spec 2026-11-02): what leaves or locks harder while travelling.
            if summary.travelHidden || summary.travelGuard {
                Image(systemName: summary.travelHidden ? "airplane" : "lock.shield")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help(summary.travelHidden ? "item.travel.hidden" : "item.travel.guard")
                    .accessibilityLabel(summary.travelHidden ? Text("item.travel.hidden") : Text("item.travel.guard"))
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(showsCustomIcon ? Text("list.row.customIcon") : Text(verbatim: ""))
        .accessibilityIdentifier("list.row.\(summary.title)")
        .task(id: taskID) {
            let id = taskID
            resolved = ResolvedIcon(id: id, data: await model.iconLoader.icon(for: id.url, title: id.title, custom: id.custom))
        }
    }
}

/// "Icône de la catégorie" draws the category artwork, unless the person chose an icon: a chosen
/// icon comes first (spec 2026-11-14 part D). "Réinitialiser l'icône" brings the category back.
extension FfiItemSummary {
    var usesCategoryIcon: Bool { iconCategory && CustomIconKey(self) == nil }
}

extension FfiItem {
    var usesCategoryIcon: Bool { iconCategory && CustomIconKey(self) == nil }
}

/// What an icon task follows: the item's address, its title (the pack's brand names) and its chosen
/// icon (a new one is a new key).
struct ItemIconTaskID: Equatable {
    let url: String?
    let title: String
    let custom: CustomIconKey?
}

extension ItemIconTaskID {
    init(_ summary: FfiItemSummary) {
        self.init(url: summary.primaryUrl, title: summary.title, custom: CustomIconKey(summary))
    }
}

/// The automatic icon an icon task found, with what it was found for. Never the chosen icon: that
/// one is read from `CustomIconStore` at each frame, so a lock or sign out (`removeAll`) leaves no
/// copy in view state.
struct ResolvedIcon: Equatable {
    let id: ItemIconTaskID
    let data: Data?
    /// Distinct per answer, so a chosen icon that just loaded redraws the view even when the
    /// automatic icon is unchanged.
    let answer = UUID()
}

extension ItemIconResolver {
    /// What an item's icon view draws: the chosen icon in memory now, else the automatic icon its
    /// task found for `id` (one found for an older address or title is ignored), else the automatic
    /// icon already on this device.
    func shownIcon(_ id: ItemIconTaskID, resolved: ResolvedIcon?) -> Data? {
        if let chosen = chosenIcon(id.custom) { return chosen }
        if let resolved, resolved.id == id { return resolved.data }
        return cachedIcon(for: id.url, title: id.title, custom: nil)
    }
}

/// Hands `content` the item's icon already on this device (`ItemIconResolver.cachedIcon`, the
/// chosen icon first), loads the chosen icon from the vault in its task, then hands it again. For
/// rows that draw a cached icon only; one that does not load leaves the automatic icon.
struct ItemIconSource<Content: View>: View {
    @Environment(AppModel.self) private var model
    let url: String?
    let title: String
    let custom: CustomIconKey?
    @ViewBuilder var content: (Data?) -> Content
    /// Bumped when a load settles: the icon is read again.
    @State private var loads = 0

    var body: some View {
        let _ = loads
        content(model.iconLoader.cachedIcon(for: url, title: title, custom: custom))
            .task(id: custom) {
                guard let custom, let store = model.iconLoader.custom, store.cached(custom) == nil else { return }
                await store.prefetch(custom)
                loads &+= 1
            }
    }
}

extension ItemIconSource {
    /// The icon of a list row. `chosen` false: the automatic icon only (a row of another account).
    init(_ summary: FfiItemSummary, chosen: Bool = true, @ViewBuilder content: @escaping (Data?) -> Content) {
        self.init(
            url: summary.primaryUrl, title: summary.title, custom: chosen ? CustomIconKey(summary) : nil,
            content: content)
    }
}

extension View {
    /// A favorite's star on the bottom-right corner of an item icon: an amber star cut into the
    /// icon (a transparent outline around it, so it reads on any row background, selected or not).
    func favoriteBadge(_ isFavorite: Bool, iconSize: CGFloat) -> some View {
        modifier(FavoriteBadge(isOn: isFavorite, iconSize: iconSize))
    }
}

private struct FavoriteBadge: ViewModifier {
    let isOn: Bool
    let iconSize: CGFloat

    static let amber = Color(red: 0xF5 / 255, green: 0xA6 / 255, blue: 0x23 / 255)

    private var star: CGFloat { iconSize * 0.32 }
    /// The gap cut around the star, so it reads on any row background, selected or not.
    private var ring: CGFloat { max(1.25, iconSize * 0.04) }
    /// The star's center, mostly over the icon, its tips just past the corner.
    private var center: CGFloat { iconSize * 0.87 }

    func body(content: Content) -> some View {
        if isOn {
            content
                .mask {
                    ZStack(alignment: .topLeading) {
                        Rectangle()
                        placed(StarShape().fill(.black).overlay {
                            StarShape().stroke(.black, style: StrokeStyle(lineWidth: ring * 2, lineJoin: .round))
                        })
                        .blendMode(.destinationOut)
                    }
                    .compositingGroup()
                }
                .overlay(alignment: .topLeading) {
                    // A thin stroke of the same amber rounds the tips.
                    placed(StarShape().fill(Self.amber).overlay {
                        StarShape().stroke(Self.amber, style: StrokeStyle(lineWidth: star * 0.08, lineJoin: .round))
                    })
                    .accessibilityLabel(Text("Favori"))
                }
        } else {
            content
        }
    }

    private func placed(_ view: some View) -> some View {
        view.frame(width: star, height: star).position(x: center, y: center)
    }
}

/// A five-pointed star drawn as a path: its cut-out ring and its fill share the same geometry.
private struct StarShape: Shape {
    func path(in rect: CGRect) -> Path {
        let center = CGPoint(x: rect.midX, y: rect.midY + rect.height * 0.04)
        let outer = min(rect.width, rect.height) / 2
        let inner = outer * 0.48
        var path = Path()
        for i in 0..<10 {
            let radius = i.isMultiple(of: 2) ? outer : inner
            let angle = -Double.pi / 2 + Double(i) * .pi / 5
            let point = CGPoint(x: center.x + radius * cos(angle), y: center.y + radius * sin(angle))
            if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
        }
        path.closeSubpath()
        return path
    }
}
