import Foundation
@testable import VaultKit

/// `createAccountWithKdf` on a thread with the core's large stack, for test fixtures that are
/// synchronous.
///
/// Account creation signs with the SLH-DSA identity key, which keeps big arrays on the stack in
/// a debug core. Called straight from an async test it runs on a 512 KiB Swift concurrency
/// thread and can overflow it (SIGBUS in `MailboxMigrationTests.Fixture.init`, seen in the full
/// run of 2026-11-03). The calling thread waits; the work never needs the cooperative pool.
func createAccountOnCoreStack(dbPath: String, password: String, kdf: FfiKdfParams) throws -> FfiCreatedAccount {
    final class Box: @unchecked Sendable { var result: Result<FfiCreatedAccount, Error>? }
    let box = Box()
    let done = DispatchSemaphore(value: 0)
    let thread = Thread {
        box.result = Result { try createAccountWithKdf(dbPath: dbPath, password: password, kdf: kdf) }
        done.signal()
    }
    thread.stackSize = CoreThread.stackSize
    thread.name = "me.somalabs.onepass.tests.core"
    thread.start()
    done.wait()
    return try box.result!.get()
}
