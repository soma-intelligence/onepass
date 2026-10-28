#if os(iOS)
import SwiftUI
import VaultKit
import VisionKit

/// Reads the QR code of the Emergency Kit with the camera (`DataScannerViewController`, spec 7).
/// Only a version 1 OnePass kit payload is accepted; anything else is ignored. Nothing is stored.
/// `accept` swaps the payload check (the pairing QR, milestone 2b): it gives what `onKey` receives,
/// or nil to ignore the code.
struct SecretKeyScanner: UIViewControllerRepresentable {
    let onKey: (String) -> Void
    var accept: (String) -> String? = EmergencyKit.parsePayload

    /// False on the Simulator and on devices without a supported camera: the button is hidden.
    @MainActor static var isSupported: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onKey: onKey, accept: accept) }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onKey: (String) -> Void
        private let accept: (String) -> String?
        private var delivered = false

        init(onKey: @escaping (String) -> Void, accept: @escaping (String) -> String?) {
            self.onKey = onKey
            self.accept = accept
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard !delivered else { return }
            for item in addedItems {
                guard case .barcode(let barcode) = item, let payload = barcode.payloadStringValue,
                    let key = accept(payload)
                else { continue }
                delivered = true
                dataScanner.stopScanning()
                onKey(key)
                return
            }
        }
    }
}

/// The scanner in a sheet with a cancel button.
struct SecretKeyScannerSheet: View {
    let onKey: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            SecretKeyScanner(onKey: onKey)
                .ignoresSafeArea()
                .navigationTitle("QR code du kit")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { dismiss() }
                    }
                }
        }
    }
}
#endif
