package me.somalabs.onepass.vault

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import me.somalabs.onepass.vaultkit.pairing.PairingConnector
import me.somalabs.onepass.vaultkit.pairing.PairingFrame
import me.somalabs.onepass.vaultkit.pairing.PairingListener
import me.somalabs.onepass.vaultkit.pairing.TcpPairingConnector
import me.somalabs.onepass.vaultkit.pairing.TcpPairingListener

/**
 * Pairing over the local network, as the iPhone and the Mac do it (spec 2b
 * 5.5): a DNS-SD service `_onepass-pair._tcp` named by the session id in hex
 * (Android's NSD), and TCP with length-prefixed frames. Nothing leaves the
 * local network; the core encrypts every frame end to end.
 */
object LanPairing {
    fun listener(context: Context): PairingListener {
        val nsd = context.getSystemService(NsdManager::class.java)
        return TcpPairingListener { name, port ->
            val info = NsdServiceInfo().apply {
                serviceName = name
                serviceType = PairingFrame.SERVICE_TYPE
                setPort(port)
            }
            val registration = object : NsdManager.RegistrationListener {
                override fun onServiceRegistered(info: NsdServiceInfo) {}
                override fun onRegistrationFailed(info: NsdServiceInfo, error: Int) {}
                override fun onServiceUnregistered(info: NsdServiceInfo) {}
                override fun onUnregistrationFailed(info: NsdServiceInfo, error: Int) {}
            }
            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registration)
            AutoCloseable { runCatching { nsd.unregisterService(registration) } }
        }
    }

    fun connector(context: Context): PairingConnector {
        val nsd = context.getSystemService(NsdManager::class.java)
        return TcpPairingConnector { name, timeoutMs ->
            val found = AtomicReference<InetSocketAddress?>()
            val done = CountDownLatch(1)
            val discovery = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(type: String) {}
                override fun onDiscoveryStopped(type: String) {}
                override fun onStartDiscoveryFailed(type: String, error: Int) { done.countDown() }
                override fun onStopDiscoveryFailed(type: String, error: Int) {}
                override fun onServiceLost(info: NsdServiceInfo) {}
                override fun onServiceFound(info: NsdServiceInfo) {
                    if (info.serviceName != name) return
                    resolve(nsd, info) { address ->
                        if (address != null && found.compareAndSet(null, address)) done.countDown()
                    }
                }
            }
            nsd.discoverServices(PairingFrame.SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
            try {
                done.await(timeoutMs, TimeUnit.MILLISECONDS)
            } finally {
                runCatching { nsd.stopServiceDiscovery(discovery) }
            }
            found.get()
        }
    }

    @Suppress("DEPRECATION")
    private fun resolve(nsd: NsdManager, info: NsdServiceInfo, done: (InetSocketAddress?) -> Unit) {
        nsd.resolveService(info, object : NsdManager.ResolveListener {
            override fun onResolveFailed(info: NsdServiceInfo, error: Int) = done(null)
            override fun onServiceResolved(info: NsdServiceInfo) {
                val host = if (Build.VERSION.SDK_INT >= 34) info.hostAddresses.firstOrNull() else info.host
                done(host?.let { InetSocketAddress(it, info.port) })
            }
        })
    }
}
