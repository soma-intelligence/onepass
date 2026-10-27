import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import VaultKit

/// Barcode field: the value and its format.
struct BarcodeEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var parts: (value: String, format: FfiBarcodeFormat) {
        if case .barcode(let v, let f) = value { (v, f) } else { ("", .qr) }
    }

    private var text: Binding<String> {
        Binding(
            get: { parts.value },
            set: { value = $0.isEmpty ? .empty : .barcode(value: $0, format: parts.format) })
    }

    private var format: Binding<FfiBarcodeFormat> {
        Binding(
            get: { parts.format },
            set: { f in if !parts.value.isEmpty { value = .barcode(value: parts.value, format: f) } })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField(field.displayLabel, text: text, prompt: Text("Valeur du code"))
                .font(.body.monospaced())
                .fieldInput(.text)
                .accessibilityIdentifier("editor.field.\(field.id)")
            Picker("Format", selection: format) {
                ForEach(BarcodeRenderer.formats, id: \.self) { Text(BarcodeRenderer.name($0)).tag($0) }
            }
            .pickerStyle(.menu)
            .disabled(parts.value.isEmpty)
        }
    }
}

/// CoreImage generators for QR, Code 128, PDF417 and Aztec. EAN-13 has none: shown as text.
enum BarcodeRenderer {
    static let formats: [FfiBarcodeFormat] = [.qr, .code128, .pdf417, .aztec, .ean13]

    static func name(_ format: FfiBarcodeFormat) -> String {
        switch format {
        case .qr: "QR code"
        case .code128: "Code 128"
        case .pdf417: "PDF417"
        case .aztec: "Aztec"
        case .ean13: "EAN-13"
        }
    }

    /// A crisp bitmap (one pixel per module, scaled by the view without smoothing), or nil.
    static func image(_ value: String, format: FfiBarcodeFormat) -> CGImage? {
        let data = Data(value.utf8)
        let output: CIImage?
        switch format {
        case .qr:
            let filter = CIFilter.qrCodeGenerator()
            filter.message = data
            filter.correctionLevel = "M"
            output = filter.outputImage
        case .code128:
            // Code 128 carries ASCII only.
            guard let ascii = value.data(using: .ascii) else { return nil }
            let filter = CIFilter.code128BarcodeGenerator()
            filter.message = ascii
            filter.quietSpace = 4
            output = filter.outputImage
        case .pdf417:
            let filter = CIFilter.pdf417BarcodeGenerator()
            filter.message = data
            output = filter.outputImage
        case .aztec:
            let filter = CIFilter.aztecCodeGenerator()
            filter.message = data
            output = filter.outputImage
        case .ean13:
            return nil
        }
        guard let output else { return nil }
        return CIContext(options: [.useSoftwareRenderer: false]).createCGImage(output, from: output.extent)
    }
}

/// The large display of a barcode: the generated image on white, the value below.
struct BarcodeLargeView: View {
    let label: String
    let value: String
    let format: FfiBarcodeFormat
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 20) {
            Text(label).font(.headline)
            if let image = BarcodeRenderer.image(value, format: format) {
                Image(decorative: image, scale: 1)
                    .resizable()
                    .interpolation(.none)
                    .aspectRatio(contentMode: .fit)
                    .padding(16)
                    .background(.white, in: RoundedRectangle(cornerRadius: 12))
                    .frame(maxWidth: 360, maxHeight: format == .qr || format == .aztec ? 360 : 180)
                    .accessibilityLabel(Text("\(BarcodeRenderer.name(format)) : \(value)"))
            }
            Text(value)
                .font(.system(format == .ean13 ? .largeTitle : .title3, design: .monospaced))
                .multilineTextAlignment(.center)
                .minimumScaleFactor(0.4)
                .textSelection(.enabled)
            Text(BarcodeRenderer.name(format)).font(.footnote).foregroundStyle(.secondary)
            Button("Fermer") { dismiss() }.keyboardShortcut(.cancelAction)
        }
        .padding(28)
        .presentationDetents([.large])
    }
}
