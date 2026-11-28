package me.somalabs.onepass.vaultkit.sync

import com.sun.jna.Native
import me.somalabs.onepass.core.FfiConverterTypeFfiMailboxEndpoint
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.RustBuffer
import me.somalabs.onepass.core.UniffiRustCallStatus

/**
 * `test_mailbox_start()` of the host library built with `dev-fast-kdf`: an
 * in-process fake mailbox served over loopback TLS (name `localhost`, the
 * test CA of `onepass-mailbox`). The generated bindings describe the shipped
 * API only, so this one test function is bound here by hand.
 */
internal object TestMailboxLib {
    init {
        Native.register(TestMailboxLib::class.java, "onepass_ffi")
    }

    @Suppress("FunctionName")
    external fun uniffi_onepass_ffi_fn_func_test_mailbox_start(uniffi_out_err: UniffiRustCallStatus): RustBuffer.ByValue
}

internal fun testMailboxStart(): FfiMailboxEndpoint {
    val status = UniffiRustCallStatus()
    val buf = TestMailboxLib.uniffi_onepass_ffi_fn_func_test_mailbox_start(status)
    check(status.isSuccess()) { "test_mailbox_start failed" }
    return FfiConverterTypeFfiMailboxEndpoint.liftFromRustBuffer(buf)
}
