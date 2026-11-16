import DesignKit
import SwiftUI
import VaultKit

/// The current one-time code ("123 • 456") and its countdown (a ring in the editor, a ring pill in
/// the detail), refreshed every second. The secret itself is never shown here.
struct TotpCodeView: View {
    let secret: String
    var compact = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// RX look: the big monospaced code and the 40 pt timer ring of the mock.
    @Environment(\.rxCards) private var rxCards

    var body: some View {
        #if os(iOS) || os(macOS)
        if rxCards, !compact {
            rxBody
        } else {
            classicBody
        }
        #else
        classicBody
        #endif
    }

    /// The RX code: "538 262" in the Mono code typography, the seconds left in a ring on the right.
    private var rxBody: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 1.0 : 1.0 / 30)) { context in
            if let code = Self.code(secret, at: context.date) {
                let exact = Self.exactRemaining(period: code.period, at: context.date)
                HStack {
                    Text(verbatim: Self.spaced(code.code))
                        .rxFont(.monoCode)
                        .foregroundStyle(Theme.RX.Palette.textPrimary.color)
                        .contentTransition(.numericText())
                        .animation(.snappy(duration: 0.35), value: code.code)
                        .accessibilityLabel(Text("term.oneTimeCode"))
                        .accessibilityValue(Text(verbatim: code.code))
                    Spacer(minLength: Theme.RX.Space.s)
                    RXTimerRing(remaining: Int(code.remaining), fraction: exact / Double(max(code.period, 1)))
                }
            } else {
                Text("item.invalidSecretPasteBase32")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// "538262" gives "538  262" (two spaces, the mock's gap); other lengths are split in halves.
    static func spaced(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<half]) + "  " + String(code[half...])
    }

    private var classicBody: some View {
        // Every frame while shown, so the ring drains smoothly; once a second with Reduce Motion.
        TimelineView(.animation(minimumInterval: reduceMotion ? 1.0 : 1.0 / 30)) { context in
            if let code = Self.code(secret, at: context.date) {
                HStack(spacing: Theme.Space.m) {
                    Text(verbatim: Self.grouped(code.code))
                        .font(compact ? .callout.monospacedDigit() : .title3.monospacedDigit())
                        .contentTransition(.numericText())
                        .animation(.snappy(duration: 0.35), value: code.code)
                        .accessibilityLabel(Text("term.oneTimeCode"))
                        .accessibilityValue(Text(verbatim: code.code))
                    if compact {
                        TotpRing(remaining: Int(code.remaining), period: Int(code.period), exact: reduceMotion ? nil : Self.exactRemaining(period: code.period, at: context.date))
                    } else {
                        TotpCountdown(remaining: Int(code.remaining), period: Int(code.period), exact: reduceMotion ? nil : Self.exactRemaining(period: code.period, at: context.date))
                    }
                }
            } else {
                Text("item.invalidSecretPasteBase32")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Seconds left in the current period, with their fraction.
    static func exactRemaining(period: UInt32, at date: Date) -> Double {
        let length = Double(max(period, 1))
        return length - date.timeIntervalSince1970.truncatingRemainder(dividingBy: length)
    }

    /// Cheap core call (HMAC), fine on the main actor.
    static func code(_ secret: String, at date: Date) -> FfiTotpCode? {
        try? totpNow(secretOrUri: secret, unixSeconds: UInt64(max(0, date.timeIntervalSince1970)))
    }

    /// "123456" gives "123 • 456" (mockup); other lengths are split in two halves.
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<half]) + " • " + String(code[half...])
    }
}

/// The RX countdown: a faint track, the accent arc draining, the seconds in the middle; red over
/// the last five seconds.
private struct RXTimerRing: View {
    let remaining: Int
    let fraction: Double

    var body: some View {
        let color = remaining <= 5 ? Theme.RX.Palette.negative.color : Theme.RX.Palette.accent.color
        ZStack {
            Circle().stroke(Theme.RX.Palette.textTertiary.color.opacity(0.4), lineWidth: 3)
            Circle()
                .trim(from: 0, to: min(max(fraction, 0), 1))
                .stroke(color, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(remaining, format: .number)
                .rxFont(.footnoteBold)
                .monospacedDigit()
                .foregroundStyle(remaining <= 5 ? color : Theme.RX.Palette.accentText.color)
        }
        .frame(width: 40, height: 40)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("encore \(remaining) secondes"))
    }
}

/// Detail row of a one-time code field: label, live code with its countdown pill, Copier (the code).
/// While the screen is captured (iOS, visionOS) the code is drawn as bullets; Copier still works.
struct TotpFieldView: View {
    let field: FfiField
    var captured = false
    let onCopy: (String) -> Void

    var body: some View {
        DetailRow(
            label: field.displayLabel.detailLabelCase, copyIdentifier: "field.copy.\(field.id)",
            copyLabel: Text("Copier le code"), onCopy: copyCurrent, showsMenu: false
        ) {
            if captured {
                Text(verbatim: FieldRow.mask)
                    .font(.title3.monospacedDigit())
                    .accessibilityLabel(Text("term.oneTimeCode"))
                    .accessibilityValue(Text("item.hidden2"))
            } else {
                TotpCodeView(secret: field.value.text)
            }
        } accessory: {
            EmptyView()
        } menu: {
            EmptyView()
        }
    }

    private func copyCurrent() {
        if let code = TotpCodeView.code(field.value.text, at: Date()) { onCopy(code.code) }
    }
}
