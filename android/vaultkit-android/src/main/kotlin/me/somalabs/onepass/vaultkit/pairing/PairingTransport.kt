package me.somalabs.onepass.vaultkit.pairing

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap

/**
 * One pairing connection, carrying opaque frames (spec 2b 5.5, iOS
 * `PairingTransport`). The end-to-end encryption lives in the core: a
 * transport only moves bytes, in order, and says when the other side is gone.
 */
interface PairingTransport {
    /** Throws [PairingClosed] once either side closed. */
    fun send(frame: ByteArray)

    /**
     * The next frame, at most `maxBytes` long (a longer one closes the
     * connection before its body is read), within `timeoutMs` (0: no limit).
     */
    fun receive(maxBytes: Int = PairingFrame.MAX_BYTES, timeoutMs: Long = 0): ByteArray

    fun close()
}

class PairingClosed(message: String = "closed") : IOException(message)
class PairingNotFound : IOException("not found")

object PairingFrame {
    /** Largest frame accepted on any transport (64 MiB; a snapshot is 50 MiB at most). */
    const val MAX_BYTES = 64 shl 20
    /** Largest frame before the key exchange is validated (the Hello, the key exchange). */
    const val MAX_HANDSHAKE_BYTES = 16 shl 10
    /** The Bonjour type of device pairing, as on iPhone and Mac. */
    const val SERVICE_TYPE = "_onepass-pair._tcp"
}

/**
 * Pairing over the local network, as the Apple apps do it: TCP, each frame
 * carrying a 4-byte big-endian length prefix, refused above the reader's cap
 * before its body is read.
 */
class SocketPairingTransport(private val socket: Socket) : PairingTransport {
    private val input = DataInputStream(socket.getInputStream().buffered())
    private val output = DataOutputStream(socket.getOutputStream().buffered())

    init {
        socket.tcpNoDelay = true
    }

    override fun send(frame: ByteArray) {
        if (frame.size > PairingFrame.MAX_BYTES) {
            close()
            throw PairingClosed("frame too large")
        }
        try {
            synchronized(output) {
                output.writeInt(frame.size)
                output.write(frame)
                output.flush()
            }
        } catch (e: IOException) {
            throw PairingClosed(e.message ?: "closed")
        }
    }

    override fun receive(maxBytes: Int, timeoutMs: Long): ByteArray = synchronized(input) {
        try {
            socket.soTimeout = timeoutMs.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
            val length = input.readInt()
            if (length < 0 || length > minOf(maxBytes, PairingFrame.MAX_BYTES)) {
                close()
                throw PairingClosed("frame too large")
            }
            ByteArray(length).also { input.readFully(it) }
        } catch (e: SocketTimeoutException) {
            close()
            throw PairingClosed("timeout")
        } catch (e: PairingClosed) {
            throw e
        } catch (e: IOException) {
            throw PairingClosed(e.message ?: "closed")
        }
    }

    override fun close() {
        runCatching { socket.close() }
    }
}

/** The side that publishes a service and takes connections (the host showing a code). */
fun interface PairingListener {
    /** Publishes `serviceName` and hands over every connection until the result is closed. */
    fun open(serviceName: String, onConnection: (PairingTransport) -> Unit): AutoCloseable
}

/** The side that finds a published service and connects to it. */
fun interface PairingConnector {
    /** Throws [PairingNotFound] when no device published `serviceName` within `timeoutMs`. */
    fun connect(serviceName: String, timeoutMs: Long): PairingTransport
}

/**
 * A TCP listener on an ephemeral port; `publish` advertises it under the
 * service name (Android: NSD `_onepass-pair._tcp`; tests: [LoopbackDirectory]).
 */
class TcpPairingListener(
    private val bind: InetAddress? = null,
    private val publish: (serviceName: String, port: Int) -> AutoCloseable,
) : PairingListener {
    override fun open(serviceName: String, onConnection: (PairingTransport) -> Unit): AutoCloseable {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress(bind, 0))
        val published = try {
            publish(serviceName, server.localPort)
        } catch (e: Exception) {
            server.close()
            throw e
        }
        val accepting = Thread({
            while (!server.isClosed) {
                val socket = try {
                    server.accept()
                } catch (_: IOException) {
                    break
                }
                runCatching { onConnection(SocketPairingTransport(socket)) }.onFailure { runCatching { socket.close() } }
            }
        }, "onepass-pair-accept").apply { isDaemon = true; start() }
        return AutoCloseable {
            runCatching { published.close() }
            runCatching { server.close() }
            accepting.interrupt()
        }
    }
}

/** A TCP connector; `resolve` finds the address of a service name (Android: NSD). */
class TcpPairingConnector(
    private val resolve: (serviceName: String, timeoutMs: Long) -> InetSocketAddress?,
) : PairingConnector {
    override fun connect(serviceName: String, timeoutMs: Long): PairingTransport {
        val started = System.currentTimeMillis()
        val address = resolve(serviceName, timeoutMs) ?: throw PairingNotFound()
        val left = (timeoutMs - (System.currentTimeMillis() - started)).coerceAtLeast(2_000)
        val socket = Socket()
        try {
            socket.connect(address, left.toInt())
        } catch (e: IOException) {
            runCatching { socket.close() }
            throw PairingNotFound()
        }
        return SocketPairingTransport(socket)
    }
}

/** Tests and single-host runs: service names resolved to loopback ports in this process. */
object LoopbackDirectory {
    private val ports = ConcurrentHashMap<String, Int>()

    val listener = TcpPairingListener(InetAddress.getLoopbackAddress()) { name, port ->
        ports[name] = port
        AutoCloseable { ports.remove(name, port) }
    }

    val connector = TcpPairingConnector { name, timeoutMs ->
        val until = System.currentTimeMillis() + timeoutMs
        var port = ports[name]
        while (port == null && System.currentTimeMillis() < until) {
            Thread.sleep(50)
            port = ports[name]
        }
        port?.let { InetSocketAddress(InetAddress.getLoopbackAddress(), it) }
    }
}
