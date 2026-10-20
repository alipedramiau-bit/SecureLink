package com.securelink.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.securelink.app.MainActivity
import com.securelink.app.R
import com.securelink.app.data.ProfileStore
import com.securelink.app.data.ProfileType
import com.securelink.app.data.VpnProfile
import com.securelink.app.vpn.l2tp.L2tpClient

/**
 * سرویس VpnService برای کلاینت L2TP.
 *
 * جریان کار:
 *  1) VpnEngine.connectL2tp سرویس را با ACTION_CONNECT و شناسه پروفایل استارت می‌کند
 *  2) سرویس L2tpClient را راه می‌اندازد (SCCRQ تا IPCP)
 *  3) هنگام onTunNeeded، establish() صدا زده شده و fd به کلاینت برمی‌گردد
 *  4) قطع با ACTION_DISCONNECT
 */
class L2tpVpnService : VpnService() {

    private var client: L2tpClient? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // برای احترام به قرارداد startForegroundService، در همه مسیرها Foreground شروع می‌شود
        startForegroundCompat()

        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopClient("قطع توسط کاربر")
                stopForegroundCompat()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val profileId = intent?.getStringExtra(EXTRA_PROFILE_ID)
                val profile = ProfileStore.findById(profileId)
                if (profile == null || profile.type != ProfileType.L2TP) {
                    Log.w(TAG, "profile not found for L2TP connect")
                    VpnEngine.l2tpActiveProfileId = null
                    VpnEngine.notifyChanged()
                    stopForegroundCompat()
                    stopSelf()
                    return START_NOT_STICKY
                }
                startClient(profile)
                return START_NOT_STICKY
            }
        }
    }

    override fun onDestroy() {
        stopClient(null)
        super.onDestroy()
    }

    override fun onRevoke() {
        // کاربر از تنظیمات سیستم مجوز VPN را لغو کرد
        stopClient("مجوز VPN لغو شد")
        VpnEngine.l2tpActiveProfileId = null
        VpnEngine.notifyChanged()
        stopForegroundCompat()
        stopSelf()
        super.onRevoke()
    }

    // ------------------------------------------------------------------

    private fun startClient(profile: VpnProfile) {
        if (client?.isRunning() == true) {
            Log.w(TAG, "L2TP client already running")
            return
        }
        VpnEngine.l2tpActiveProfileId = profile.id
        VpnEngine.notifyChanged()

        val l2tpClient = L2tpClient(
            profile = profile,
            serverAddress = profile.l2tpServer,
            protector = { socket -> protect(socket) },
            callbacks = object : L2tpClient.Callbacks {
                override fun onPhase(phase: String) {
                    Log.d(TAG, "phase=$phase")
                }

                override fun onTunNeeded(config: L2tpClient.TunConfig): ParcelFileDescriptor? {
                    return try {
                        establishVpn(config)
                    } catch (t: Throwable) {
                        Log.e(TAG, "establish failed", t)
                        null
                    }
                }

                override fun onClosed(error: String?) {
                    if (VpnEngine.l2tpActiveProfileId == profile.id) {
                        VpnEngine.l2tpActiveProfileId = null
                    }
                    stopForegroundCompat()
                    stopSelf()
                    VpnEngine.notifyChanged()
                }
            }
        )
        client = l2tpClient
        l2tpClient.start()
    }

    private fun stopClient(reason: String?) {
        client?.shutdown(reason)
        client = null
    }

    private fun establishVpn(config: L2tpClient.TunConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("SecureLink L2TP")
            .setMtu(config.mtu)
            .addAddress(config.address, 32)
            .addRoute("0.0.0.0", 0)
        builder.addDnsServer(config.dns1)
        if (config.dns2 != config.dns1) builder.addDnsServer(config.dns2)
        // سوکت UDP کلاینت با protect() از تونل عبور می‌کند؛ حالت پیش‌فرض (blocking) حفظ می‌شود
        return builder.establish()
    }

    // ------------------------------------------------------------------
    // اعلان Foreground
    // ------------------------------------------------------------------

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun startForegroundCompat() {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_l2tp_connecting))
            .setOngoing(true)
            .setContentIntent(pending)
            .build()
        val type = if (Build.VERSION.SDK_INT >= 34) {
            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
    }

    private fun stopForegroundCompat() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    companion object {
        private const val TAG = "SecureLink-L2TP-Svc"
        private const val CHANNEL_ID = "securelink_vpn"
        private const val NOTIFICATION_ID = 42

        const val ACTION_CONNECT = "com.securelink.app.l2tp.CONNECT"
        const val ACTION_DISCONNECT = "com.securelink.app.l2tp.DISCONNECT"
        const val EXTRA_PROFILE_ID = "profileId"

        fun start(context: Context, profileId: String) {
            val intent = Intent(context, L2tpVpnService::class.java)
                .setAction(ACTION_CONNECT)
                .putExtra(EXTRA_PROFILE_ID, profileId)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, L2tpVpnService::class.java)
                .setAction(ACTION_DISCONNECT)
            try {
                // از UI (پیش‌زمینه) صدا زده می‌شود؛ startForegroundService لازم نیست
                context.startService(intent)
            } catch (t: Throwable) {
                Log.d(TAG, "stop: service not running")
            }
        }
    }
}
