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
    /// two lines. Scanning starts once the view is on screen (VisionKit refuses earlier); a refusal
    /// (camera denied or busy, device without the scanner) goes to `onFailure`, so the screen can
    /// offer to type the lines instead. Check `DataScannerViewController.isSupported` and
    /// `.isAvailable` first.
    public struct MRZScanner: UIViewControllerRepresentable {
        private let onMRZ: @MainActor ([String]) -> Void
        private let onFailure: @MainActor (any Error) -> Void

        public init(
            onMRZ: @escaping @MainActor ([String]) -> Void,
            onFailure: @escaping @MainActor (any Error) -> Void
        ) {
            self.onMRZ = onMRZ
            self.onFailure = onFailure
        }

        public func makeUIViewController(context: Context) -> Host {
            let scanner = DataScannerViewController(
                recognizedDataTypes: [.text()], qualityLevel: .accurate,
                recognizesMultipleItems: true, isHighFrameRateTrackingEnabled: false,
                isHighlightingEnabled: false)
            scanner.delegate = context.coordinator
            return Host(scanner: scanner, onFailure: onFailure)
        }

        public func updateUIViewController(_ host: Host, context: Context) {}

        public static func dismantleUIViewController(_ host: Host, coordinator: Coordinator) {
            host.scanner.stopScanning()
        }

        public func makeCoordinator() -> Coordinator { Coordinator(onMRZ: onMRZ, onFailure: onFailure) }

        /// Holds the scanner as a child and starts it once visible: `startScanning()` throws while
        /// the scanner is not in a window yet.
        public final class Host: UIViewController {
            let scanner: DataScannerViewController
            private let onFailure: @MainActor (any Error) -> Void
            private var started = false

            init(scanner: DataScannerViewController, onFailure: @escaping @MainActor (any Error) -> Void) {
                self.scanner = scanner
                self.onFailure = onFailure
                super.init(nibName: nil, bundle: nil)
            }

            @available(*, unavailable)
            required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

            public override func viewDidLoad() {
                super.viewDidLoad()
                addChild(scanner)
                scanner.view.frame = view.bounds
                scanner.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
                view.addSubview(scanner.view)
                scanner.didMove(toParent: self)
            }

            public override func viewDidAppear(_ animated: Bool) {
                super.viewDidAppear(animated)
                guard !started else { return }
                started = true
                do {
                    try scanner.startScanning()
                } catch {
                    onFailure(error)
                }
            }

            public override func viewWillDisappear(_ animated: Bool) {
                super.viewWillDisappear(animated)
                scanner.stopScanning()
                started = false
            }
        }

        @MainActor
        public final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            private var accumulator = MRZAccumulator()
            private var done = false
            private let onMRZ: @MainActor ([String]) -> Void
            private let onFailure: @MainActor (any Error) -> Void

            init(onMRZ: @escaping @MainActor ([String]) -> Void, onFailure: @escaping @MainActor (any Error) -> Void) {
                self.onMRZ = onMRZ
                self.onFailure = onFailure
            }

            public func dataScanner(
                _ scanner: DataScannerViewController, didAdd added: [RecognizedItem],
                allItems: [RecognizedItem]
            ) { feed(allItems) }

            public func dataScanner(
                _ scanner: DataScannerViewController, didUpdate updated: [RecognizedItem],
                allItems: [RecognizedItem]
            ) { feed(allItems) }

            public func dataScanner(
                _ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable
            ) {
                // The camera went away while scanning (access revoked, another app took it).
                guard !done else { return }
                done = true
                onFailure(error)
            }

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
