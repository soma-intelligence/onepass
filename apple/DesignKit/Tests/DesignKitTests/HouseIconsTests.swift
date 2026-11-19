import Foundation
import SwiftUI
import Testing

@testable import DesignKit

#if canImport(UIKit)
    import UIKit
#elseif canImport(AppKit)
    import AppKit
#endif

@Suite("HouseIcons")
struct HouseIconsTests {
    @Test func catalogHasFortyUniqueIds() {
        #expect(HouseIcons.all.count == 40)
        #expect(Set(HouseIcons.all.map(\.id)).count == 40)
    }

    @Test func everySymbolResolves() {
        for icon in HouseIcons.all {
            #if canImport(UIKit)
                #expect(UIImage(systemName: icon.symbol) != nil, "\(icon.id): \(icon.symbol)")
            #elseif canImport(AppKit)
                #expect(NSImage(systemSymbolName: icon.symbol, accessibilityDescription: nil) != nil, "\(icon.id): \(icon.symbol)")
            #endif
        }
    }

    @MainActor
    @Test func renderIsA256PixelPng() throws {
        for icon in HouseIcons.all {
            let data = HouseIcons.render(icon, colorIndex: 3, scheme: .light)
            #expect(data.count > 0 && data.count < 64 * 1024, "\(icon.id): \(data.count) bytes")
            #expect(Array(data.prefix(8)) == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            let b = Array(data)
            let width = b[16...19].reduce(0) { $0 << 8 | Int($1) }
            let height = b[20...23].reduce(0) { $0 << 8 | Int($1) }
            #expect(width == 256 && height == 256, "\(icon.id)")
        }
    }

    @MainActor
    @Test func colorIndexWrapsAndSchemeChangesPixels() {
        let icon = HouseIcons.all[0]
        #expect(HouseIcons.render(icon, colorIndex: 14, scheme: .light) == HouseIcons.render(icon, colorIndex: 2, scheme: .light))
        #expect(HouseIcons.render(icon, colorIndex: -1, scheme: .light) == HouseIcons.render(icon, colorIndex: 11, scheme: .light))
        #expect(HouseIcons.render(icon, colorIndex: 2, scheme: .light) != HouseIcons.render(icon, colorIndex: 2, scheme: .dark))
    }

    @MainActor
    @Test func symbolIsDrawnOnTheTile() {
        let outputs = Set(HouseIcons.all.map { HouseIcons.render($0, colorIndex: 0, scheme: .light) })
        #expect(outputs.count == HouseIcons.all.count)
    }
}
