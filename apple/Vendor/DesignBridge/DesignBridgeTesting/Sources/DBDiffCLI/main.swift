import CoreGraphics
import DBDiff
import Foundation

let usage = """
usage: dbdiff <reference> <candidate> [options]

Compares app screenshots against Penpot @3x PNG exports with SSIM and an offset tolerance,
then writes an HTML report with side-by-side and diff images.

<reference> and <candidate> are two PNG files, or two folders paired by file name
(Settings@3x.png matches settings.png).

options:
  --out <dir>             report folder (default: dbdiff-report)
  --config <file>         parity.json, or a designbridge.json with a "parity" key
  --ssim <value>          minimum SSIM (default 0.97)
  --max-offset-pt <pt>    largest tolerated layout offset in points (default 1)
  --scale <n>             pixels per point (default 3)
  --mask <x,y,w,h>        region to ignore, in points; repeatable
  --color <rgb|luma>      SSIM on the mean of R, G, B (default) or on luma only
  --no-resize             fail on size mismatch instead of resampling the candidate
  --report-only           always exit 0 (report mode before a component becomes a gate)
  -h, --help              show this help

exit codes: 0 all pairs pass, 1 a pair fails or is missing, 2 usage or I/O error
"""

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("dbdiff: \(message)\n".utf8))
    exit(2)
}

var positionals: [String] = []
var out = "dbdiff-report"
var configPath: String?
var explicit = VisualDiff.ExplicitOptions()
var base = ComparisonOptions()
var reportOnly = false

var args = Array(CommandLine.arguments.dropFirst())
@MainActor func value(_ flag: String) -> String {
    guard !args.isEmpty else { fail("\(flag) needs a value") }
    return args.removeFirst()
}
@MainActor func number(_ flag: String) -> Double {
    let raw = value(flag)
    guard let v = Double(raw) else { fail("\(flag) expects a number, got \(raw)") }
    return v
}

while !args.isEmpty {
    let arg = args.removeFirst()
    switch arg {
    case "-h", "--help":
        print(usage)
        exit(0)
    case "--out": out = value(arg)
    case "--config": configPath = value(arg)
    case "--ssim": explicit.ssim = number(arg)
    case "--max-offset-pt": explicit.maxOffsetPt = number(arg)
    case "--scale": explicit.scale = number(arg)
    case "--mask":
        let parts = value(arg).split(separator: ",").compactMap { Double($0.trimmingCharacters(in: .whitespaces)) }
        guard parts.count == 4 else { fail("--mask expects x,y,w,h in points") }
        base.masks.append(CGRect(x: parts[0], y: parts[1], width: parts[2], height: parts[3]))
    case "--color":
        let raw = value(arg)
        guard let mode = SSIM.ColorMode(rawValue: raw) else { fail("--color expects rgb or luma, got \(raw)") }
        base.colorMode = mode
    case "--no-resize": base.resizeCandidate = false
    case "--report-only": reportOnly = true
    default:
        if arg.hasPrefix("-") { fail("unknown option \(arg)\n\n\(usage)") }
        positionals.append(arg)
    }
}

guard positionals.count == 2 else { fail("expected <reference> and <candidate>\n\n\(usage)") }

do {
    let config = try configPath.map { try ParityConfig.load(URL(fileURLWithPath: $0)) } ?? ParityConfig()
    let output = URL(fileURLWithPath: out, isDirectory: true)
    let summary = try VisualDiff.run(
        reference: URL(fileURLWithPath: positionals[0]),
        candidate: URL(fileURLWithPath: positionals[1]),
        output: output,
        config: config,
        base: base,
        explicit: explicit
    )
    for row in summary.rows {
        let mark = row.passed ? "PASS" : "FAIL"
        let ssim = row.ssim.map { String(format: "SSIM %.4f", $0) } ?? "SSIM n/a"
        let offset = row.offsetPt.map { String(format: "offset %.2f pt", $0) } ?? ""
        let problems = row.problems.isEmpty ? "" : "  (" + row.problems.joined(separator: "; ") + ")"
        print("\(mark)  \(row.name)  \(ssim)  \(offset)\(problems)")
    }
    print("\(summary.passed) passed, \(summary.failed) failed. Report: \(output.appendingPathComponent("index.html").path)")
    exit(summary.failed == 0 || reportOnly ? 0 : 1)
} catch {
    fail("\(error)")
}
