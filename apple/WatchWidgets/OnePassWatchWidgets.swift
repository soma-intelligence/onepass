import SwiftUI
import WidgetKit

/// Complication and Smart Stack card: the OnePass glyph and name, no vault data. Tapping it
/// opens the app.
@main
struct OnePassWatchWidgets: WidgetBundle {
    var body: some Widget {
        OnePassLauncherWidget()
    }
}

struct OnePassLauncherWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "me.somalabs.onepass.watch.launcher", provider: LauncherProvider()) { _ in
            LauncherView()
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("OnePass")
        .description("Ouvre OnePass.")
        .supportedFamilies([.accessoryCircular, .accessoryCorner, .accessoryRectangular])
    }
}

struct LauncherEntry: TimelineEntry {
    let date: Date
}

struct LauncherProvider: TimelineProvider {
    func placeholder(in context: Context) -> LauncherEntry { LauncherEntry(date: .now) }

    func getSnapshot(in context: Context, completion: @escaping (LauncherEntry) -> Void) {
        completion(LauncherEntry(date: .now))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<LauncherEntry>) -> Void) {
        completion(Timeline(entries: [LauncherEntry(date: .now)], policy: .never))
    }
}

struct LauncherView: View {
    @Environment(\.widgetFamily) private var family

    var body: some View {
        switch family {
        case .accessoryCorner:
            Image(systemName: "lock.shield")
                .font(.title2)
                .widgetLabel("OnePass")
                .accessibilityLabel("OnePass")
        case .accessoryRectangular:
            HStack(spacing: 6) {
                Image(systemName: "lock.shield")
                    .font(.title2)
                    .accessibilityHidden(true)
                Text("OnePass")
                    .font(.headline)
                    .widgetAccentable()
                Spacer(minLength: 0)
            }
        default:
            ZStack {
                AccessoryWidgetBackground()
                Image(systemName: "lock.shield")
                    .font(.title2)
                    .widgetAccentable()
            }
            .accessibilityLabel("OnePass")
        }
    }
}
