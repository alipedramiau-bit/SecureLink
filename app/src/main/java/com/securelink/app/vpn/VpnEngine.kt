package com.securelink.app.vpn

import android.content.Context
import android.content.Intent
import android.net.Ikev2VpnProfile
import android.net.VpnManager
import android.net.VpnService
import android.os.Build
import androidx.annotation.RequiresApi
import com.securelink.app.data.IkeAuthType
import com.securelink.app.data.VpnProfile
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/**
 * لایه ارتباط با موتورهای VPN:
 *
 *  1) WireGuard  → کتابخانه رسمی wireguard-android (GoBackend / userspace)
 *     https://github.com/WireGuard/wireguard-android
 *
 *  2) IKEv2/IPSec → موتور بومی اندروید (VpnManager + Ikev2VpnProfile) از اندروید ۱۱ به بالا.
 *
 *  3) L2TP/PPP   → کلاینت خالص Kotlin در پکیج vpn.l2tp (برای MikroTik های قدیمی)
 *     که روی سرویس L2tpVpnService اجرا می‌شود.
 */
object VpnEngine {

    private val executor = Executors.newSingleThreadExecutor()
    private var backend: GoBackend? = null

    /** شناسه پروفایل IKEv2 در حال اجرا (فقط در حافظه؛ پس از ری‌استارت پروسه پاک می‌شود) */
    @Volatile
    var ikeActiveProfileId: String? = null
        private set

    /** شناسه پروفایل L2TP در حال اجرا — توسط L2tpVpnService مدیریت می‌شود */
    @Volatile
    var l2tpActiveProfileId: String? = null

    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun addListener(listener: () -> Unit) { listeners.add(listener) }
    fun removeListener(listener: () -> Unit) { listeners.remove(listener) }
    fun notifyChanged() { listeners.forEach { it.invoke() } }

    // ------------------------------------------------------------------
    // WireGuard
    // ------------------------------------------------------------------

    private fun backend(context: Context): GoBackend {
        var b = backend
        if (b == null) {
            synchronized(this) {
                b = backend ?: GoBackend(context.applicationContext).also { backend = it }
            }
        }
        return b!!
    }

    /** Intent اجازه VPN سیستم؛ اگر null باشد یعنی قبلاً مجوز داده شده است. */
    fun prepareWireGuardPermission(context: Context): Intent? =
        VpnService.prepare(context.applicationContext)

    fun isWireGuardRunning(context: Context, profile: VpnProfile): Boolean = try {
        backend(context).getRunningTunnelNames().contains(profile.tunnelName())
    } catch (_: Exception) {
        false
    }

    fun anyWireGuardRunning(context: Context): Boolean = try {
        backend(context).getRunningTunnelNames().isNotEmpty()
    } catch (_: Exception) {
        false
    }

    fun connectWireGuard(
        context: Context,
        profile: VpnProfile,
        onDone: (success: Boolean, error: String?) -> Unit
    ) {
        executor.execute {
            try {
                // فقط یک VPN همزمان: اگر L2TP فعال است ابتدا قطع شود
                stopL2tp(context)
                val b = backend(context)
                val config = Config.parse(
                    ByteArrayInputStream(profile.wgConfigText.toByteArray(Charsets.UTF_8))
                )
                // GoBackend خودش در صورت وجود تانل فعال قبلی، آن را پایین می‌آورد
                val tunnel = SimpleTunnel(profile.tunnelName())
                val state = b.setState(tunnel, Tunnel.State.UP, config)
                ikeActiveProfileId = null
                onDone(state == Tunnel.State.UP, null)
            } catch (t: Throwable) {
                onDone(false, friendlyError(t))
            } finally {
                notifyChanged()
            }
        }
    }

    fun disconnectWireGuard(
        context: Context,
        profile: VpnProfile,
        onDone: (success: Boolean, error: String?) -> Unit
    ) {
        executor.execute {
            try {
                val b = backend(context)
                if (b.getRunningTunnelNames().contains(profile.tunnelName())) {
                    b.setState(SimpleTunnel(profile.tunnelName()), Tunnel.State.DOWN, null)
                }
                onDone(true, null)
            } catch (t: Throwable) {
                onDone(false, friendlyError(t))
            } finally {
                notifyChanged()
            }
        }
    }

    private class SimpleTunnel(private val tunnelName: String) : Tunnel {
        override fun getName(): String = tunnelName
        override fun onStateChange(newState: Tunnel.State) { /* وضعیت از طریق listener اپ مدیریت می‌شود */ }
    }

    /** توقف همه تانل‌های فعال WireGuard (برای گذر به پروتکل دیگر). */
    fun stopAllWireGuard(context: Context) {
        try {
            val b = backend(context)
            for (name in b.getRunningTunnelNames()) {
                try {
                    b.setState(SimpleTunnel(name), Tunnel.State.DOWN, null)
                } catch (_: Throwable) { }
            }
        } catch (_: Throwable) { }
        notifyChanged()
    }

    // ------------------------------------------------------------------
    // IKEv2 / IPSec (اندروید ۱۱+)
    // ------------------------------------------------------------------

    val isIkev2Supported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    fun isIkev2Active(profileId: String?): Boolean = ikeActiveProfileId != null && ikeActiveProfileId == profileId

    fun isAnyIkev2Active(): Boolean = ikeActiveProfileId != null

    /**
     * پروفایل IKEv2 را در سیستم provision می‌کند.
     * اگر کاربر قبلاً اجازه نداده باشد، Intent کادر مجوز برگردانده می‌شود؛
     * پس از تأیید (onActivityResult) باید startIkev2 فراخوانی شود.
     */
    fun provisionIkev2(context: Context, profile: VpnProfile): Intent? {
        requireIkev2Support()
        val manager = vpnManager(context)
        return manager.provisionVpnProfile(Ikev2Helper.buildProfile(profile))
    }

    fun startIkev2(context: Context, profile: VpnProfile, onDone: (Boolean, String?) -> Unit) {
        try {
            requireIkev2Support()
            // فقط یک VPN همزمان
            if (isAnyL2tpActive()) stopL2tp(context)
            // پس از تأیید مجوز توسط کاربر، پروفایل دوباره provision و سپس استارت می‌شود
            val manager = vpnManager(context)
            manager.provisionVpnProfile(Ikev2Helper.buildProfile(profile))
            manager.startProvisionedVpnProfile()
            ikeActiveProfileId = profile.id
            onDone(true, null)
        } catch (t: Throwable) {
            ikeActiveProfileId = null
            onDone(false, friendlyError(t))
        } finally {
            notifyChanged()
        }
    }

    fun stopIkev2(context: Context, onDone: (Boolean, String?) -> Unit) {
        try {
            requireIkev2Support()
            vpnManager(context).deleteProvisionedVpnProfile()
            ikeActiveProfileId = null
            onDone(true, null)
        } catch (t: Throwable) {
            onDone(false, friendlyError(t))
        } finally {
            notifyChanged()
        }
    }

    private fun requireIkev2Support() {
        check(isIkev2Supported) { "IKEv2 نیاز به اندروید ۱۱ (API 30) یا بالاتر دارد" }
    }
    private fun vpnManager(context: Context): VpnManager =
        context.getSystemService(VpnManager::class.java)
            ?: throw IllegalStateException("سرویس VpnManager در این دستگاه در دسترس نیست")

    /**
     * همه کدهای مرتبط با کلاس‌های API-30 در یک شیء مجزا نگه داشته شده‌اند
     * تا روی دستگاه‌های قدیمی‌تر مشکل verifier پیش نیاید.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    private object Ikev2Helper {
        fun buildProfile(p: VpnProfile): Ikev2VpnProfile {
            val identity = p.ikeIdentity.ifBlank { p.ikeServer }
            val builder = Ikev2VpnProfile.Builder(p.ikeServer.trim(), identity.trim())
            when (p.ikeAuthType) {
                IkeAuthType.USERNAME_PASSWORD ->
                    builder.setAuthUsernamePassword(p.ikeUsername.trim(), p.ikePassword, null)
                IkeAuthType.PSK ->
                    builder.setAuthPsk(p.ikePsk.toByteArray(Charsets.UTF_8))
            }
            builder.setBypassable(true)
            builder.setMetered(false)
            return builder.build()
        }
    }

    // ------------------------------------------------------------------
    // L2TP / PPP (برای MikroTik RouterOS قدیمی)
    // ------------------------------------------------------------------

    fun isL2tpActive(profileId: String?): Boolean =
        profileId != null && l2tpActiveProfileId != null && l2tpActiveProfileId == profileId

    fun isAnyL2tpActive(): Boolean = l2tpActiveProfileId != null

    /** Intent اجازه VPN سیستم؛ اگر null باشد یعنی قبلاً مجوز داده شده است. */
    fun prepareL2tpPermission(context: Context): Intent? =
        VpnService.prepare(context.applicationContext)

    /**
     * شروع اتصال L2TP؛ خودِ سرویس L2tpVpnService کلاینت را اجرا می‌کند.
     * نتیجه از طریق listener (notifyChanged) به UI منعکس می‌شود.
     */
    fun connectL2tp(context: Context, profile: VpnProfile) {
        // فقط یک VPN همزمان
        executor.execute { stopAllWireGuard(context) }
        L2tpVpnService.start(context.applicationContext, profile.id)
    }

    /** قطع اتصال L2TP (اگر فعال باشد). */
    fun stopL2tp(context: Context) {
        if (isAnyL2tpActive()) {
            L2tpVpnService.stop(context.applicationContext)
        }
    }

    // ------------------------------------------------------------------

    private fun friendlyError(t: Throwable): String {
        val reasonName = (t as? com.wireguard.android.backend.BackendException)?.reason?.name
        return when (reasonName) {
            "VPN_NOT_AUTHORIZED" -> "مجوز VPN توسط کاربر تأیید نشده است"
            "TUNNEL_MISSING_CONFIG" -> "کانفیگ نامعتبر یا ناقص است"
            "UNABLE_TO_START_VPN" -> "شروع سرویس VPN ممکن نشد؛ دسترسی VPN را بررسی کنید"
            else -> {
                val message = t.message?.takeIf { it.isNotBlank() } ?: t.javaClass.simpleName
                "${t.javaClass.simpleName}: $message"
            }
        }
    }
}
