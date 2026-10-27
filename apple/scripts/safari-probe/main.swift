// End-to-end stand-in for the Safari extension handler, never shipped
// (extension/test/bridge/app-safari.test.ts). Build and sign it with the
// team's identity as me.somalabs.onepass.safari (App Group entitlement):
//
//   swiftc -O -module-name SafariProbe apple/SafariExtension/SafariRelay/Sources/SafariRelay/*.swift apple/scripts/safari-probe/main.swift -o safari-probe
//   codesign -f -s <identity> -o runtime -i me.somalabs.onepass.safari --entitlements <group> safari-probe
//
// JSON lines {"id":n,"msg":{...}} in, {"id":n,"reply":{...}} out, each request
// served concurrently, as Safari delivers sendNativeMessage requests.
import Foundation

let hub = RelayHub(launcher: BridgeHost.launcher(), pollTimeout: 20)
let out = NSLock()
let queue = DispatchQueue(label: "probe", attributes: .concurrent)
FileHandle.standardError.write("launcher: \(String(describing: BridgeHost.launcher()))\n".data(using: .utf8)!)
while let line = readLine() {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
        let id = obj["id"] as? Int
    else { continue }
    let msg = obj["msg"]
    queue.async {
        let reply = hub.handle(message: msg).dictionary
        let data = try! JSONSerialization.data(withJSONObject: ["id": id, "reply": reply])
        out.lock()
        FileHandle.standardOutput.write(data + Data("\n".utf8))
        out.unlock()
    }
}
// stdin closed: let in-flight requests finish.
Thread.sleep(forTimeInterval: 1)
