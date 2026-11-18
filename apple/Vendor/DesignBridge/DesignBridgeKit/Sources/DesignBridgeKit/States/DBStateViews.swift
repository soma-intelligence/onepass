import SwiftUI

/// Timings and values for loading states (UX-STATE-02, UX-STATE-03).
public enum DBStates {
    /// The spinner appears only if loading lasts longer than this.
    public static let spinnerDelay: Duration = .milliseconds(400)
    /// Shimmer opacity range and full cycle.
    public static let shimmerOpacity: ClosedRange<Double> = 0.4...0.7
    public static let shimmerCycle: TimeInterval = 1.4
}

/// The empty state: one line of what this is and one action to fill it (UX-STATE-04).
public struct DBEmptyState: Sendable {
    public var title: String
    public var systemImage: String
    public var message: String?
    public var actionTitle: String
    public var action: @MainActor @Sendable () -> Void

    public init(
        _ title: String,
        systemImage: String,
        message: String? = nil,
        actionTitle: String,
        action: @escaping @MainActor @Sendable () -> Void
    ) {
        self.title = title
        self.systemImage = systemImage
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
    }
}

/// Switches a `DBLoadable` to its view. Every data view goes through it, so
/// none of the four states can be forgotten (UX-STATE-01).
///
/// ```swift
/// DBLoadableView(model.items, empty: DBEmptyState("No trips yet", systemImage: "airplane",
///     actionTitle: "Plan a trip") { model.plan() }, retry: { model.reload() }) { items in
///     List(items) { TripRow(trip: $0) }
/// } placeholder: {
///     List(Trip.samples) { TripRow(trip: $0) }   // redacted while loading
/// }
/// ```
public struct DBLoadableView<Value, Content: View, Placeholder: View>: View {
    private let state: DBLoadable<Value>
    private let empty: DBEmptyState
    private let retry: @MainActor @Sendable () -> Void
    private let content: (Value) -> Content
    private let placeholder: Placeholder

    @Environment(\.toast) private var toast

    public init(
        _ state: DBLoadable<Value>,
        empty: DBEmptyState,
        retry: @escaping @MainActor @Sendable () -> Void,
        @ViewBuilder content: @escaping (Value) -> Content,
        @ViewBuilder placeholder: () -> Placeholder
    ) {
        self.state = state
        self.empty = empty
        self.retry = retry
        self.content = content
        self.placeholder = placeholder()
    }

    public var body: some View {
        Group {
            switch state.phase {
            case .skeleton:
                DBLoadingView { placeholder }
            case .empty:
                DBEmptyView(empty)
            case .failed:
                DBErrorView(state.error ?? .generic, retry: retry)
            case .refreshing, .failedOverContent, .content:
                if let value = state.value {
                    content(value)
                }
            }
        }
        .onChange(of: state.error, initial: true) { _, error in
            // An error over existing content is never silent: toast it with Retry.
            guard let error, state.phase == .failedOverContent else { return }
            toast(.error(error.message, action: DBToastButton(DBStrings.retry, handler: retry)))
        }
    }
}

public extension DBLoadableView where Placeholder == DBSkeleton {
    /// Uses the generic skeleton rows as the loading placeholder.
    init(
        _ state: DBLoadable<Value>,
        empty: DBEmptyState,
        retry: @escaping @MainActor @Sendable () -> Void,
        @ViewBuilder content: @escaping (Value) -> Content
    ) {
        self.init(state, empty: empty, retry: retry, content: content) { DBSkeleton() }
    }
}

/// Loading: the placeholder redacted with a subtle shimmer, and a spinner that
/// appears only after 400 ms (UX-STATE-02).
public struct DBLoadingView<Placeholder: View>: View {
    private let placeholder: Placeholder

    public init(@ViewBuilder placeholder: () -> Placeholder) {
        self.placeholder = placeholder()
    }

    public var body: some View {
        ZStack {
            placeholder
                .redacted(reason: .placeholder)
                .dbShimmer()
                .allowsHitTesting(false)
            DBDelayedSpinner()
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(DBStrings.loading))
    }
}

/// A spinner that stays invisible for `DBStates.spinnerDelay`, so fast loads never flash.
public struct DBDelayedSpinner: View {
    private let delay: Duration
    @State private var isVisible = false

    public init(delay: Duration = DBStates.spinnerDelay) {
        self.delay = delay
    }

    public var body: some View {
        ProgressView()
            .opacity(isVisible ? 1 : 0)
            .task {
                try? await Task.sleep(for: delay)
                isVisible = true
            }
    }
}

/// Generic skeleton rows for when no real placeholder layout is given.
public struct DBSkeleton: View {
    private let rows: Int
    @Environment(\.dbTheme) private var theme

    public init(rows: Int = 5) {
        self.rows = rows
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.l) {
            ForEach(0..<rows, id: \.self) { index in
                VStack(alignment: .leading, spacing: theme.spacing.s) {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(theme.skeleton)
                        .frame(height: 16)
                        .frame(maxWidth: index.isMultiple(of: 2) ? .infinity : 240, alignment: .leading)
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(theme.skeleton)
                        .frame(width: 140, height: 12)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(theme.spacing.l)
        .dbShimmer()
        .accessibilityHidden(true)
    }
}

/// Empty state built on `ContentUnavailableView`, with its one action.
public struct DBEmptyView: View {
    private let state: DBEmptyState

    public init(_ state: DBEmptyState) {
        self.state = state
    }

    public var body: some View {
        ContentUnavailableView {
            Label(state.title, systemImage: state.systemImage)
        } description: {
            if let message = state.message {
                Text(message)
            }
        } actions: {
            // Inside content, so no glass (UX-GLASS-01).
            Button(state.actionTitle, action: state.action)
                .buttonStyle(.borderedProminent)
        }
    }
}

/// Error state: what happened, in plain words, and a Retry (UX-STATE-05).
public struct DBErrorView: View {
    private let error: DBLoadError
    private let retryTitle: String
    private let retry: @MainActor @Sendable () -> Void

    public init(_ error: DBLoadError, retryTitle: String = DBStrings.tryAgain, retry: @escaping @MainActor @Sendable () -> Void) {
        self.error = error
        self.retryTitle = retryTitle
        self.retry = retry
    }

    public var body: some View {
        ContentUnavailableView {
            Label(error.title, systemImage: "exclamationmark.triangle")
        } description: {
            Text(error.message)
        } actions: {
            Button(retryTitle, action: retry)
                .buttonStyle(.borderedProminent)
        }
    }
}

// MARK: - Shimmer

public extension View {
    /// Pulses opacity between 0.4 and 0.7 over 1.4 s; holds still under Reduce Motion (UX-STATE-03).
    func dbShimmer() -> some View {
        modifier(DBShimmerModifier())
    }
}

private struct DBShimmerModifier: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        if reduceMotion {
            content.opacity((DBStates.shimmerOpacity.lowerBound + DBStates.shimmerOpacity.upperBound) / 2)
        } else {
            content.phaseAnimator([DBStates.shimmerOpacity.upperBound, DBStates.shimmerOpacity.lowerBound]) { view, opacity in
                view.opacity(opacity)
            } animation: { _ in
                .easeInOut(duration: DBStates.shimmerCycle / 2)
            }
        }
    }
}
