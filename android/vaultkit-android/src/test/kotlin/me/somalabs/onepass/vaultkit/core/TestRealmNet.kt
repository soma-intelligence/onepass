package me.somalabs.onepass.vaultkit.core

import com.sun.jna.Native
import me.somalabs.onepass.core.FfiConverterTypeFfiRealmTransport
import me.somalabs.onepass.core.FfiRealmTransport
import me.somalabs.onepass.core.UniffiRustCallStatus

/**
 * `FfiTestRealmNet` of the host library built with `dev-fast-kdf`: three
 * realms in this process, pinned in place of the build's list while the
 * network lives. The generated bindings describe the shipped API only, so
 * the constructor and `transport()` are bound here by hand (as
 * `test_mailbox_start` in TestMailbox.kt).
 */
internal object TestRealmNetLib {
    init {
        Native.register(TestRealmNetLib::class.java, "onepass_ffi")
    }

    @Suppress("FunctionName")
    external fun uniffi_onepass_ffi_fn_constructor_ffitestrealmnet_new(uniffi_out_err: UniffiRustCallStatus): Long

    @Suppress("FunctionName")
    external fun uniffi_onepass_ffi_fn_clone_ffitestrealmnet(handle: Long, uniffi_out_err: UniffiRustCallStatus): Long

    @Suppress("FunctionName")
    external fun uniffi_onepass_ffi_fn_free_ffitestrealmnet(handle: Long, uniffi_out_err: UniffiRustCallStatus)

    @Suppress("FunctionName")
    external fun uniffi_onepass_ffi_fn_method_ffitestrealmnet_transport(ptr: Long, uniffi_out_err: UniffiRustCallStatus): Long
}

/** The test realm network; `close()` frees it. */
internal class TestRealmNet : AutoCloseable {
    private val handle: Long = run {
        val status = UniffiRustCallStatus()
        val h = TestRealmNetLib.uniffi_onepass_ffi_fn_constructor_ffitestrealmnet_new(status)
        check(status.isSuccess()) { "FfiTestRealmNet::new failed" }
        h
    }

    /** The transport to hand to the guard calls. */
    fun transport(): FfiRealmTransport {
        val status = UniffiRustCallStatus()
        // The method consumes the handle it is given: hand it a clone.
        val clone = TestRealmNetLib.uniffi_onepass_ffi_fn_clone_ffitestrealmnet(handle, status)
        check(status.isSuccess()) { "FfiTestRealmNet clone failed" }
        val t = TestRealmNetLib.uniffi_onepass_ffi_fn_method_ffitestrealmnet_transport(clone, status)
        check(status.isSuccess()) { "FfiTestRealmNet::transport failed" }
        return FfiConverterTypeFfiRealmTransport.lift(t)
    }

    override fun close() {
        val status = UniffiRustCallStatus()
        TestRealmNetLib.uniffi_onepass_ffi_fn_free_ffitestrealmnet(handle, status)
    }
}
