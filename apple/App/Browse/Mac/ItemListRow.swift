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
    @State private var siteIcon: Data?

    init(summary: FfiItemSummary, vaultName: String?) {
        self.summary = summary
        self.vaultName = vaultName
    }

    /// A login with no username that signs in with a provider: "Se connecte avec GitHub".
    private var signInLine: String? {
        guard summary.subtitle.isEmpty, let provider = summary.signInProvider else { return nil }
        return String(localized: "Se connecte avec \(LoginProvider.displayName(provider))")
    }

    private var secondLine: String {
        let line = signInLine ?? summary.subtitle
        return line.isEmpty ? ItemCategory.of(summary.itemType).singular : line
    }

    /// The icon already on this device: shown on the first frame, before the task answers.
    private var cachedIcon: Data? {
        summary.primaryUrl.flatMap { model.iconLoader.cachedIcon(for: $0) }
    }

    var body: some View {
        HStack(spacing: 12) {
            ItemIcon(type: summary.itemType, title: summary.title, siteIcon: siteIcon ?? cachedIcon, size: 34, brand: summary.cardBrand)
                .favoriteBadge(summary.favorite, iconSize: 34)
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
                    .help(summary.travelHidden ? "Caché en voyage" : "Protection renforcée en voyage")
                    .accessibilityLabel(summary.travelHidden ? Text("Caché en voyage") : Text("Protection renforcée en voyage"))
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("list.row.\(summary.title)")
        .task(id: summary.primaryUrl) {
            guard let url = summary.primaryUrl else {
                siteIcon = nil
                return
            }
            siteIcon = await model.iconLoader.icon(for: url)
        }
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
