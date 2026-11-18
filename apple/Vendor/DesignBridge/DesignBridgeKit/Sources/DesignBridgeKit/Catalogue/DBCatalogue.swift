import SwiftUI

/// Every DesignBridgeKit primitive on one screen, for previews and for a
/// debug menu in apps: `NavigationStack { DBCatalogueView() }.dbToastHost()`.
public struct DBCatalogueView: View {
    public init() {}

    public var body: some View {
        List {
            Section("Toast") { ToastDemo() }
            Section("Number") { NumberDemo() }
            Section("Motion and haptics") { MotionDemo() }
            Section("States") { StatesDemo() }
            Section("Glass") { GlassDemo() }
            Section("Text") { TextDemo() }
            Section("Navigation") {
                NavigationLink("Scroll hero") { ScrollHeroDemo() }
                NavigationLink("Zoom transition") { ZoomDemo() }
            }
        }
        .navigationTitle("DesignBridgeKit")
        .dbTruncationLogging()
    }
}

// MARK: - Demos

private struct ToastDemo: View {
    @Environment(\.toast) private var toast
    @State private var items = 3

    var body: some View {
        Button("Copy a code") { toast.copyToClipboard("4815 1623 42", label: "Code copied") }
        Button("Info") { toast(.info("Sync paused")) }
        Button("Delete with Undo") {
            items -= 1
            toast(.undo("Item deleted") { items += 1 })
        }
        Button("Error with Retry") {
            toast(.error("Couldn't save. Check your connection.", action: DBToastButton("Retry") {
                toast(.success("Saved"))
            }))
        }
        LabeledContent("Items", value: "\(items)")
    }
}

private struct NumberDemo: View {
    @State private var count = 1_280
    @State private var balance = 1_234.5
    @State private var score = 0.82
    @State private var step = 0

    var body: some View {
        LabeledContent("Steps") { DBNumber(count) }
        LabeledContent("Balance") { DBNumber(balance, currencyCode: "EUR") }
        LabeledContent("Score") { DBNumber(score, format: .percent()) }
        Button("Change") {
            // A fixed cycle, not a random draw: OnePass forbids OS random draws in apple/ (rng_guard).
            let deltas = [640, -220, 870, -90, 310]
            step = (step + 1) % deltas.count
            count += deltas[step]
            balance += Double(deltas[step] * 3) / 10
            score = Double(step + 1) / Double(deltas.count + 1)
        }
        .dbHaptic(.increase, trigger: count)
    }
}

private struct MotionDemo: View {
    @State private var expanded = false
    @State private var choice = 0

    var body: some View {
        Button {
            expanded.toggle()
        } label: {
            Label(expanded ? "Collapse" : "Expand", systemImage: expanded ? "chevron.up" : "chevron.down")
        }
        .buttonStyle(.dbPress)
        .dbHaptic(.commit, trigger: expanded)
        if expanded {
            Text("Springs: snappy 0.25 s, smooth 0.4 s, bouncy 0.45 s.")
                .foregroundStyle(.secondary)
                .dbTransition(edge: .top)
        }
        Picker("Spring", selection: $choice) {
            ForEach(DBSpring.all.indices, id: \.self) { Text(DBSpring.all[$0].name).tag($0) }
        }
        #if !os(watchOS)
        .pickerStyle(.segmented)
        #endif
        .dbHaptic(.selection, trigger: choice)
        .dbAnimation(DBSpring.all[choice], value: expanded)
    }
}

private struct StatesDemo: View {
    private enum Pick: String, CaseIterable { case loading, empty, error, content }
    @State private var pick = Pick.content

    private var state: DBLoadable<[String]> {
        switch pick {
        case .loading: .initial
        case .empty: .empty
        case .error: .failed(.offline, previous: nil)
        case .content: .content(["Lisbon", "Kyoto", "Oaxaca"])
        }
    }

    var body: some View {
        Picker("State", selection: $pick) {
            ForEach(Pick.allCases, id: \.self) { Text($0.rawValue).tag($0) }
        }
        #if !os(watchOS)
        .pickerStyle(.segmented)
        #endif
        DBLoadableView(
            state,
            empty: DBEmptyState("No trips yet", systemImage: "airplane", actionTitle: "Plan a trip") { pick = .content },
            retry: { pick = .content }
        ) { trips in
            VStack(alignment: .leading) {
                ForEach(trips, id: \.self) { Text($0) }
            }
        }
        .frame(height: 260)
    }
}

private struct GlassDemo: View {
    var body: some View {
        ZStack {
            LinearGradient(colors: [.orange, .pink, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
            DBGlassGroup(spacing: 12) {
                HStack(spacing: 12) {
                    Button("Share", systemImage: "square.and.arrow.up") {}
                        .labelStyle(.iconOnly)
                        .dbSecondaryAction()
                    Button("Continue") {}
                        .dbPrimaryAction()
                }
            }
        }
        .frame(height: 120)
        .clipShape(.rect(cornerRadius: 16, style: .continuous))
    }
}

private struct TextDemo: View {
    var body: some View {
        Text("A long label that wraps onto a second line before it ever shrinks")
            .dbText(maxLines: 2)
            .dbTruncationProbe("wrap")
        Text("Transfer to the joint savings account now")
            .dbText(maxLines: 1) {
                Text("Transfer").dbText()
            }
        DBAdaptiveStack(spacing: 8) {
            Text("Balance")
            Spacer(minLength: 0)
            DBNumber(98_765.43, currencyCode: "USD").font(.title3.bold())
        }
        Text("This one is clipped on purpose to show the probe outline")
            .lineLimit(1)
            .dbTruncationProbe("clipped-demo")
    }
}

private struct ScrollHeroDemo: View {
    var body: some View {
        DBScrollHero(heroHeight: 300) {
            LinearGradient(colors: [.teal, .indigo], startPoint: .top, endPoint: .bottom)
        } header: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Lisbon").font(.largeTitle.bold())
                Text("4 nights").font(.headline)
            }
            .foregroundStyle(.white)
        } content: {
            LazyVStack(alignment: .leading, spacing: 16) {
                ForEach(1...30, id: \.self) { day in
                    Text("Row \(day)")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(20)
        }
        .navigationTitle("Lisbon")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

private struct ZoomDemo: View {
    @Namespace private var zoom
    private let colors: [Color] = [.red, .orange, .green, .blue]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), spacing: 12)], spacing: 12) {
                ForEach(colors.indices, id: \.self) { index in
                    NavigationLink {
                        colors[index]
                            .ignoresSafeArea()
                            .navigationTitle("Card \(index + 1)")
                            .dbZoomDestination(sourceID: index, in: zoom)
                    } label: {
                        RoundedRectangle(cornerRadius: 20, style: .continuous)
                            .fill(colors[index])
                            .frame(height: 140)
                            .dbZoomSource(id: index, in: zoom)
                            .accessibilityLabel("Card \(index + 1)")
                    }
                    .buttonStyle(.dbPress)
                }
            }
            .padding(16)
        }
        .navigationTitle("Zoom")
    }
}

// MARK: - Previews

#Preview("Catalogue") {
    NavigationStack { DBCatalogueView() }
        .dbToastHost()
}

#Preview("Catalogue, dark, AX3") {
    NavigationStack { DBCatalogueView() }
        .dbToastHost()
        .preferredColorScheme(.dark)
        .dynamicTypeSize(.accessibility3)
}

#Preview("Scroll hero") {
    NavigationStack { ScrollHeroDemo() }
}

#Preview("States") {
    List { StatesDemo() }
        .dbToastHost()
}

#Preview("Zoom") {
    NavigationStack { ZoomDemo() }
}

#Preview("Themed") {
    NavigationStack { DBCatalogueView() }
        .dbToastHost()
        .dbTheme(DBStandardTheme(accent: .mint, success: .mint, sheetCornerRadius: 20))
        .tint(.mint)
}
