import SwiftUI
import WidgetKit

/// iPhone and iPad widgets and Controls (spec 7 and 8). The extension links GlanceKit only: it
/// reads the snapshot the app writes in the App Group and never sees a key or a TOTP secret.
@main
struct OnePassWidgetsBundle: WidgetBundle {
    var body: some Widget {
        CodesWidget()
        FavoritesWidget()
        GeneratorControl()
        SearchControl()
        LockControl()
    }
}
