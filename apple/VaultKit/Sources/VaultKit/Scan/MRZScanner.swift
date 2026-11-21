import Foundation
import OnePassCore

/// Turns the text a camera recognizer hands over, read after read, into the two TD3 lines of a
/// passport MRZ: they come out once three valid reads in a row agree. A read without a valid MRZ
/// is ignored (it neither counts nor breaks the run); a different valid MRZ starts over.
public struct MRZAccumulator: Sendable {
    /// Identical valid reads needed.
    static let needed = 3

    private var last: [String]?
    private var count = 0

    public init() {}

    /// Feeds one recognized text. Returns the two lines on the third identical valid read.
    public mutating func add(_ text: String) -> [String]? {
        guard let lines = Self.mrz(in: text) else { return nil }
        if lines == last {
            count += 1
        } else {
            last = lines
            count = 1
        }
        guard count >= Self.needed else { return nil }
        return lines
    }

    /// The first pair of 44-character lines that parses as a TD3 MRZ, as the core corrected it.
    static func mrz(in text: String) -> [String]? {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
        let candidates = text.split(whereSeparator: \.isNewline).map { line in
            String(line.uppercased().filter { !$0.isWhitespace })
        }
        for (a, b) in zip(candidates, candidates.dropFirst())
        where a.count == 44 && b.count == 44 && a.hasPrefix("P") && a.allSatisfy(allowed.contains)
            && b.allSatisfy(allowed.contains)
        {
            if let mrz = try? mrzParse(lines: [a, b]) { return mrz.lines }
        }
        return nil
    }
}

#if canImport(VisionKit) && os(iOS)
    import SwiftUI
    import VisionKit

    /// The camera view that reads a passport MRZ: VisionKit's DataScannerViewController
    /// (`recognizedDataTypes: [.text()]`) feeding an `MRZAccumulator`. Calls `onMRZ` once with the
    /// two lines. Check `DataScannerViewController.isSupported` and `.isAvailable` first.
    public struct MRZScanner: UIViewControllerRepresentable {
        private let onMRZ: @MainActor ([String]) -> Void

        public init(onMRZ: @escaping @MainActor ([String]) -> Void) {
            self.onMRZ = onMRZ
        }

        public func makeUIViewController(context: Context) -> DataScannerViewController {
            let scanner = DataScannerViewController(
                recognizedDataTypes: [.text()], qualityLevel: .accurate,
                recognizesMultipleItems: true, isHighFrameRateTrackingEnabled: false,
                isHighlightingEnabled: false)
            scanner.delegate = context.coordinator
            try? scanner.startScanning()
            return scanner
        }

        public func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

        public static func dismantleUIViewController(
            _ scanner: DataScannerViewController, coordinator: Coordinator
        ) {
            scanner.stopScanning()
        }

        public func makeCoordinator() -> Coordinator { Coordinator(onMRZ: onMRZ) }

        @MainActor
        public final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            private var accumulator = MRZAccumulator()
            private var done = false
            private let onMRZ: @MainActor ([String]) -> Void

            init(onMRZ: @escaping @MainActor ([String]) -> Void) {
                self.onMRZ = onMRZ
            }

            public func dataScanner(
                _ scanner: DataScannerViewController, didAdd added: [RecognizedItem],
                allItems: [RecognizedItem]
            ) { feed(allItems) }

            public func dataScanner(
                _ scanner: DataScannerViewController, didUpdate updated: [RecognizedItem],
                allItems: [RecognizedItem]
            ) { feed(allItems) }

            /// Every item on screen, top to bottom, as one text: the two MRZ lines may come as two
            /// items.
            private func feed(_ items: [RecognizedItem]) {
                guard !done else { return }
                let text = items.compactMap { item -> (CGFloat, String)? in
                    guard case .text(let t) = item else { return nil }
                    return (t.bounds.topLeft.y, t.transcript)
                }
                .sorted { $0.0 < $1.0 }
                .map(\.1)
                .joined(separator: "\n")
                if let lines = accumulator.add(text) {
                    done = true
                    onMRZ(lines)
                }
            }
        }
    }
#endif
