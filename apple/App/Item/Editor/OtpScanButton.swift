#if os(macOS)
import AppKit
import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit
import Vision

/// "Scanner un QR code" on the Mac: a small sheet that takes a pasted image, a dropped one or a
/// chosen file, finds its QR code with Vision on this Mac and hands one account's `otpauth://` link
/// to `onValue`. Nothing is sent anywhere, nothing is kept once the sheet closes.
struct OtpScanButton: View {
    let onValue: (String) -> Void
    @State private var presented = false

    var body: some View {
        Button {
            presented = true
        } label: {
            Image(systemName: "qrcode.viewfinder")
        }
        .buttonStyle(.borderless)
        .help("editor.otp.scan")
        .accessibilityLabel(Text("editor.otp.scan"))
        .accessibilityIdentifier("editor.otp.scan")
        .sheet(isPresented: $presented) {
            OtpImageScanSheet { value in
                onValue(value)
                presented = false
            }
        }
    }
}

private struct OtpImageScanSheet: View {
    let onValue: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var problem: LocalizedStringKey?
    @State private var targeted = false
    @State private var choosing = false

    var body: some View {
        VStack(spacing: Theme.Space.l) {
            Text("editor.otp.scanTitle").font(.headline)
            RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6, 4]))
                .foregroundStyle(targeted ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.tertiary))
                .frame(height: 150)
                .overlay {
                    VStack(spacing: Theme.Space.s) {
                        Image(systemName: "qrcode").font(.system(size: 34)).foregroundStyle(.secondary)
                        Text("editor.otp.dropImage").font(.callout).foregroundStyle(.secondary)
                    }
                }
                .onDrop(of: [.image, .fileURL], isTargeted: $targeted) { providers in
                    load(providers)
                    return true
                }
            if let problem {
                Label(problem, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("editor.otp.problem")
            }
            HStack {
                Button("Annuler", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("editor.otp.paste") { paste() }.keyboardShortcut("v", modifiers: .command)
                Button("editor.otp.chooseImage") { choosing = true }
            }
        }
        .padding(Theme.Space.xl)
        .frame(width: 380)
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.image]) { result in
            guard case .success(let url) = result else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            read(NSImage(contentsOf: url))
        }
    }

    private func paste() {
        read(NSImage(pasteboard: .general))
    }

    private func load(_ providers: [NSItemProvider]) {
        guard let provider = providers.first else { return }
        _ = provider.loadDataRepresentation(for: .image) { data, _ in
            let image = data.flatMap(NSImage.init(data:))
            Task { @MainActor in read(image) }
        }
    }

    private func read(_ image: NSImage?) {
        guard let image, let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            problem = "editor.otp.notOtp"
            return
        }
        Task {
            let payloads = await Self.qrPayloads(in: cgImage)
            let results = payloads.map(OtpScan.read)
            if let value = results.lazy.compactMap({ if case .value(let v) = $0 { v } else { nil } }).first {
                onValue(value)
            } else if results.contains(where: { if case .severalAccounts = $0 { true } else { false } }) {
                problem = "editor.otp.several"
            } else {
                problem = "editor.otp.notOtp"
            }
        }
    }

    /// The QR codes Vision finds in the image, on a background task.
    private static func qrPayloads(in image: CGImage) async -> [String] {
        await Task.detached(priority: .userInitiated) {
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            try? VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap(\.payloadStringValue)
        }.value
    }
}
#endif
