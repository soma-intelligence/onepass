#if os(iOS)
import AVFoundation
import SwiftUI
import VaultKit
import VisionKit

/// Reads the QR code of the Emergency Kit with the camera (`DataScannerViewController`, spec 7).
/// Only a version 1 Kelid kit payload is accepted; anything else is ignored. Nothing is stored.
/// `accept` swaps the payload check (the pairing QR, milestone 2b): it gives what `onKey` receives,
/// or nil to ignore the code.
struct SecretKeyScanner: UIViewControllerRepresentable {
    let onKey: (String) -> Void
    var accept: (String) -> String? = EmergencyKit.parsePayload

    /// False on the Simulator, on devices without a supported camera, and while camera access is
    /// denied: for the screens that embed the scanner itself.
    @MainActor static var isSupported: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    /// The device can scan, whatever the camera permission: the scan buttons show on this, and
    /// `SecretKeyScannerSheet` explains a denied access.
    @MainActor static var isDeviceSupported: Bool {
        DataScannerViewController.isSupported
    }

    /// Camera access was refused (or is restricted by Screen Time or a profile).
    static var isCameraDenied: Bool {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        return status == .denied || status == .restricted
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

    /// Started again when the first start came too early (the view not on screen yet, or the camera
    /// prompt still open): without it the preview shows but nothing is ever recognized.
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {
        guard !context.coordinator.delivered, !controller.isScanning else { return }
        try? controller.startScanning()
    }

    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onKey: onKey, accept: accept) }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onKey: (String) -> Void
        private let accept: (String) -> String?
        private(set) var delivered = false

        init(onKey: @escaping (String) -> Void, accept: @escaping (String) -> String?) {
            self.onKey = onKey
            self.accept = accept
        }

        // A code is often added before it is read (payload nil, or the pairing tile still drawing its
        // dots), then only updated: the payload arrives in `didUpdate`. A pairing QR renewed every
        // 30 s at the same place is also an update, never an add. So every callback is checked.
        func dataScanner(
            _ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            deliver(from: addedItems, scanner: dataScanner)
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            deliver(from: updatedItems, scanner: dataScanner)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            deliver(from: [item], scanner: dataScanner)
        }

        private func deliver(from items: [RecognizedItem], scanner: DataScannerViewController) {
            guard !delivered else { return }
            for item in items {
                guard case .barcode(let barcode) = item, let payload = barcode.payloadStringValue,
                    let key = accept(payload)
                else { continue }
                delivered = true
                scanner.stopScanning()
                onKey(key)
                return
            }
        }
    }
}

/// The scanner in a sheet with a cancel button. `title` and `accept` default to the Emergency Kit.
/// Asks for the camera first when it was never asked; when access is denied, says so and offers
/// to open Réglages instead of a black view.
struct SecretKeyScannerSheet: View {
    var title: LocalizedStringKey = "onboarding.kitQrCode"
    var accept: (String) -> String? = EmergencyKit.parsePayload
    let onKey: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @Environment(\.scenePhase) private var scenePhase
    @State private var access: CameraAccess = .checking

    private enum CameraAccess { case checking, granted, denied }

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { dismiss() }
                    }
                }
        }
        .task { await checkAccess() }
        // Back from Réglages with the access turned on: the scanner starts.
        .onChange(of: scenePhase) { _, phase in
            if phase == .active, access == .denied { Task { await checkAccess() } }
        }
    }

    @ViewBuilder private var content: some View {
        switch access {
        case .checking:
            ProgressView()
        case .granted:
            SecretKeyScanner(onKey: onKey, accept: accept)
                .ignoresSafeArea()
        case .denied:
            ContentUnavailableView {
                Label("scanner.cameraDenied.title", systemImage: "camera.fill")
            } description: {
                Text("scanner.cameraDenied.message")
            } actions: {
                Button("onboarding.openSettings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("scanner.openSettings")
            }
        }
    }

    private func checkAccess() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            access = .granted
        case .notDetermined:
            access = await AVCaptureDevice.requestAccess(for: .video) ? .granted : .denied
        default:
            access = .denied
        }
    }
}

extension SecretKeyScanner {
    /// A verification code QR code (`otpauth://`, `otpauth-migration://`), given as scanned.
    static func acceptOtpLink(_ payload: String) -> String? {
        OtpLink.isLink(payload) ? payload : nil
    }

    /// A QR code with exactly one verification code: its canonical `otpauth://` URI (the item
    /// editor's field takes one code).
    static func acceptSingleOtp(_ payload: String) -> String? {
        guard OtpLink.isLink(payload), let accounts = try? OtpLink.accounts(in: payload), accounts.count == 1
        else { return nil }
        return accounts[0].uri
    }
}
#endif
