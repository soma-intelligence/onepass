import DesignKit
import SwiftUI
import VaultKit

/// Tags of the item: chips with a remove button, a field to add one (Return adds), and the tags
/// already used elsewhere offered as suggestions.
struct TagEditor: View {
    @Environment(AppModel.self) private var model
    @Binding var draft: ItemDraft
    @State private var newTag = ""

    private var suggestions: [String] {
        let used = Set(draft.item.tags.map { $0.lowercased() })
        let typed = newTag.trimmingCharacters(in: .whitespaces).lowercased()
        let all = Set(model.session.summaries.flatMap(\.tags))
        return all.filter { !used.contains($0.lowercased()) && (typed.isEmpty || $0.lowercased().hasPrefix(typed)) }
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
            .prefix(6)
            .map { $0 }
    }

    var body: some View {
        FlowLayout(spacing: 8) {
            ForEach(draft.item.tags, id: \.self) { tag in
                Button {
                    draft.removeTag(tag)
                } label: {
                    HStack(spacing: 6) {
                        Text(tag)
                        Image(systemName: "xmark").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(.fill.tertiary, in: Capsule())
                }
                .buttonStyle(.plain)
                .visionHoverEffect()
                .help("Retirer le tag")
                .accessibilityLabel(Text("Retirer le tag \(tag)"))
            }
            HStack(spacing: 6) {
                Image(systemName: "plus").font(.callout.weight(.semibold))
                TextField("Tag", text: $newTag, prompt: Text("Ajouter un tag").foregroundStyle(Theme.accent.mix(with: .white, by: 0.3)))
                    .labelsHidden()
                    .textFieldStyle(.plain)
                    .onSubmit(add)
                    .fieldInput(.text)
                    .frame(width: 110)
                    .accessibilityIdentifier("editor.tag")
            }
            .foregroundStyle(Theme.accent.mix(with: .white, by: 0.3))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .overlay { Capsule().strokeBorder(Theme.accent.opacity(0.5), style: StrokeStyle(lineWidth: 1, dash: [4, 3])) }
        }
        let suggestions = suggestions
        if !suggestions.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(suggestions, id: \.self) { tag in
                        Button(tag) {
                            draft.addTag(tag)
                            newTag = ""
                        }
                        .font(.footnote)
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                    }
                }
            }
        }
    }

    private func add() {
        draft.addTag(newTag)
        newTag = ""
    }
}

/// Wraps its children onto as many lines as needed (tag chips).
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                y += line + spacing
                x = 0
                line = 0
            }
            x += size.width + spacing
            line = max(line, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: proposal.width ?? widest, height: y + line)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                y += line + spacing
                x = bounds.minX
                line = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            line = max(line, size.height)
        }
    }
}
