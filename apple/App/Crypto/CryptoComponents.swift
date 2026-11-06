import Charts
import DesignKit
import SwiftUI
import VaultKit

/// Number formatting of the Crypto screens.
enum CryptoFormat {
    static func money(_ value: Decimal, currency: String) -> String {
        let abs = value < 0 ? -value : value
        let digits = abs >= 1 || abs == 0 ? 2 : (abs >= 0.01 ? 4 : 6)
        return value.formatted(.currency(code: currency.uppercased()).precision(.fractionLength(digits)))
    }

    /// Whole part and the rest (decimal separator, cents, a trailing symbol) of a money string,
    /// for the big total with smaller cents.
    static func split(_ text: String) -> (String, String) {
        let sep = Locale.current.decimalSeparator ?? "."
        guard let r = text.range(of: sep, options: .backwards) else { return (text, "") }
        return (String(text[..<r.lowerBound]), String(text[r.lowerBound...]))
    }

    static func amount(_ value: Decimal, symbol: String) -> String {
        let digits = value >= 1000 ? 2 : (value >= 1 ? 4 : 6)
        let n = value.formatted(.number.precision(.fractionLength(0...digits)))
        return "\(n) \(symbol)"
    }

    static func percent(_ change: Double) -> String {
        (abs(change) / 100).formatted(.percent.precision(.fractionLength(2)))
    }

    /// Up green, down red (system colors: they adapt to dark mode and increased contrast).
    static func color(_ change: Double?) -> Color {
        guard let change else { return .secondary }
        return change < 0 ? .red : .green
    }

    /// `bc1qcr8t…306fyu`.
    static func short(_ address: String) -> String {
        guard address.count > 16 else { return address }
        return "\(address.prefix(8))…\(address.suffix(6))"
    }
}

/// "▼ 12,52 %" in red, "▲ 0,60 %" in green.
struct ChangeLabel: View {
    let change: Double?
    var font: Font = .subheadline

    var body: some View {
        if let change {
            HStack(spacing: 3) {
                Image(systemName: change < 0 ? "arrowtriangle.down.fill" : "arrowtriangle.up.fill")
                    .font(.system(size: 8, weight: .bold))
                Text(verbatim: CryptoFormat.percent(change))
                    .monospacedDigit()
            }
            .font(font)
            .foregroundStyle(CryptoFormat.color(change))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(change < 0
                ? Text("crypto.change.down \(CryptoFormat.percent(change))")
                : Text("crypto.change.up \(CryptoFormat.percent(change))"))
        }
    }
}

/// A rounded card on the Crypto screen: translucent over the header color, solid below it.
struct CryptoCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.regularMaterial, in: .rect(cornerRadius: 26, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 26, style: .continuous).strokeBorder(Color.primary.opacity(0.06))
            }
    }
}

/// "Titre ›" heading inside a card.
struct CryptoCardTitle: View {
    let title: LocalizedStringKey

    var body: some View {
        Text(title)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 18)
            .padding(.top, 16)
            .padding(.bottom, 4)
            .accessibilityAddTraits(.isHeader)
    }
}

/// One holding: coin mark, name, "amount SYMBOL · unit price", value and change on the right.
struct HoldingRow: View {
    let holding: CryptoHolding
    let currency: String

    var body: some View {
        HStack(spacing: 14) {
            CoinIcon(coin: holding.coin, symbol: holding.symbol, size: 42)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: holding.name).font(.body.weight(.medium)).lineLimit(1)
                Text(verbatim: subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                if let value = holding.value {
                    Text(verbatim: CryptoFormat.money(value, currency: currency))
                        .font(.body.weight(.medium))
                        .monospacedDigit()
                } else {
                    Text("crypto.noPrice").font(.subheadline).foregroundStyle(.secondary)
                }
                ChangeLabel(change: holding.change)
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String {
        let amount = CryptoFormat.amount(holding.amount, symbol: holding.symbol)
        guard let price = holding.price else { return amount }
        return "\(amount) · \(CryptoFormat.money(price, currency: currency))"
    }
}

/// Smooth line chart of a series, no axes. `baseline` draws a dotted line at the first value (the
/// period's open); `fill` puts a soft wash under the line.
struct CryptoLineChart: View {
    let points: [CryptoChartPoint]
    var color: Color = .primary
    var lineWidth: CGFloat = 2.5
    var baseline = false
    var fill = false
    @Binding var selection: Date?

    init(points: [CryptoChartPoint], color: Color = .primary, lineWidth: CGFloat = 2.5, baseline: Bool = false,
         fill: Bool = false, selection: Binding<Date?> = .constant(nil)) {
        self.points = points
        self.color = color
        self.lineWidth = lineWidth
        self.baseline = baseline
        self.fill = fill
        _selection = selection
    }

    var body: some View {
        let values = points.map(\.value)
        let lo = values.min() ?? 0, hi = values.max() ?? 1
        let pad = max((hi - lo) * 0.08, hi * 0.0005)
        Chart {
            if baseline, let first = points.first {
                RuleMark(y: .value("open", first.value))
                    .foregroundStyle(color.opacity(0.45))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [2, 4]))
            }
            ForEach(points, id: \.date) { p in
                if fill {
                    AreaMark(x: .value("t", p.date), yStart: .value("lo", lo - pad), yEnd: .value("v", p.value))
                        .interpolationMethod(.catmullRom)
                        .foregroundStyle(LinearGradient(colors: [color.opacity(0.22), color.opacity(0)],
                                                        startPoint: .top, endPoint: .bottom))
                }
                LineMark(x: .value("t", p.date), y: .value("v", p.value))
                    .interpolationMethod(.catmullRom)
                    .foregroundStyle(color)
                    .lineStyle(StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round))
            }
            if let selection, let p = nearest(selection) {
                RuleMark(x: .value("t", p.date)).foregroundStyle(color.opacity(0.35))
                PointMark(x: .value("t", p.date), y: .value("v", p.value)).foregroundStyle(color).symbolSize(60)
            }
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartLegend(.hidden)
        .chartYScale(domain: (lo - pad)...(hi + pad))
        .chartXSelection(value: $selection)
        .accessibilityHidden(true)
    }

    func nearest(_ date: Date) -> CryptoChartPoint? {
        points.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }
    }
}

/// The period switch under a chart: 24 h, 1 S, 1 M, 1 A.
struct PeriodPicker: View {
    @Binding var period: CryptoPeriod

    var body: some View {
        Picker(selection: $period) {
            ForEach(CryptoPeriod.allCases, id: \.self) { p in
                Text(Self.label(p)).tag(p)
            }
        } label: {
            Text("crypto.period")
        }
        .pickerStyle(.segmented)
        .accessibilityIdentifier("crypto.period")
    }

    static func label(_ p: CryptoPeriod) -> LocalizedStringKey {
        switch p {
        case .day: "crypto.period.day"
        case .week: "crypto.period.week"
        case .month: "crypto.period.month"
        case .year: "crypto.period.year"
        }
    }
}
