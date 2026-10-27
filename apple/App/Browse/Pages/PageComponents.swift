import DesignKit
import SwiftUI

/// Header of a full page (Watchtower, Développeur): icon tile, large title, one line of text.
struct PageHeader<Trailing: View>: View {
    let title: String
    let symbol: String
    let color: Color
    let message: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 24) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    PageTile(symbol: symbol, color: color, size: 34)
                    Text(title).font(.largeTitle.weight(.bold))
                }
                Text(message)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            trailing
        }
    }
}

extension PageHeader where Trailing == EmptyView {
    init(title: String, symbol: String, color: Color, message: String) {
        self.init(title: title, symbol: symbol, color: color, message: message) { EmptyView() }
    }
}

/// Rounded colored tile with a white symbol, like the sidebar's `CategoryTile`.
struct PageTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 28

    var body: some View {
        RoundedRectangle(cornerRadius: size * 5 / 18, style: .continuous)
            .fill(color)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }
}

/// Outlined "Voir … →" button of a page card.
struct PageLinkButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title)
                Image(systemName: "arrow.right").font(.caption.weight(.semibold))
            }
            .font(.callout.weight(.medium))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .contentShape(Capsule())
            .overlay { Capsule().strokeBorder(.secondary.opacity(0.45)) }
        }
        .buttonStyle(.plain)
    }
}

/// Code to type in a terminal, selectable, with a copy button.
struct CodeBox: View {
    let code: String
    let onCopy: (String) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(code)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                onCopy(code)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help(Text("Copier"))
            .accessibilityLabel(Text("Copier"))
        }
        .padding(12)
        .background(.black.opacity(0.18), in: .rect(cornerRadius: 10))
        .overlay { RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.07)) }
    }
}
