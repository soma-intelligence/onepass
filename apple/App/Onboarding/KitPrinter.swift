import Foundation
#if os(macOS)
import AppKit
import PDFKit
#else
import UIKit
#endif

/// Prints the Emergency Kit straight from memory (spec 4, "Imprimer le kit"): the PDF bytes go
/// to the system print panel and no file is written by the app.
@MainActor
enum KitPrinter {
    static let jobName = "Emergency Kit OnePass"

    /// Shows the system print panel for `pdf`. Returns false when printing is unavailable or the
    /// PDF cannot be read.
    @discardableResult
    static func print(_ pdf: Data) -> Bool {
        #if os(macOS)
        guard let document = PDFDocument(data: pdf),
              let info = NSPrintInfo.shared.copy() as? NSPrintInfo,
              let operation = document.printOperation(
                for: info, scalingMode: .pageScaleToFit, autoRotate: true)
        else { return false }
        operation.jobTitle = jobName
        operation.showsPrintPanel = true
        operation.showsProgressPanel = true
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            operation.runModal(for: window, delegate: nil, didRun: nil, contextInfo: nil)
        } else {
            operation.run()
        }
        return true
        #else
        guard UIPrintInteractionController.isPrintingAvailable,
              UIPrintInteractionController.canPrint(pdf)
        else { return false }
        let controller = UIPrintInteractionController.shared
        let info = UIPrintInfo.printInfo()
        info.jobName = jobName
        info.outputType = .general
        controller.printInfo = info
        controller.printingItem = pdf
        controller.present(animated: true) { controller, _, _ in
            // Drop the bytes from the shared controller once the panel closes.
            controller.printingItem = nil
        }
        return true
        #endif
    }
}
