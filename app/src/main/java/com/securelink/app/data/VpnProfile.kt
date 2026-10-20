package com.securelink.app.data

import java.util.UUID

/**
 * نوع پروتکل پروفایل.
 */
enum class ProfileType {
    WIREGUARD,
    IKEV2,
    L2TP
}

/**
 * روش احراز هویت IKEv2/IPSec.
 * USERNAME_PASSWORD معادل EAP-MSCHAPv2 در سرورهای strongSwan/Cisco است.
 */
enum class IkeAuthType {
    USERNAME_PASSWORD,
    PSK
}

/**
 * مدل داده‌ای یک پروفایل VPN که در حافظه گوشی (JSON) ذخیره می‌شود.
 */
data class VpnProfile(
    val id: String = UUID.randomUUID().toString(),
    var name: String = "",
    var type: ProfileType = ProfileType.WIREGUARD,
    // ---- WireGuard ----
    // متن کامل کانفیگ با فرمت [Interface]/[Peer] — منبع اصلی حقیقت برای اتصال وایرگارد
    var wgConfigText: String = "",
    // ---- IKEv2 / IPSec ----
    var ikeServer: String = "",
    var ikeIdentity: String = "",
    var ikeAuthType: IkeAuthType = IkeAuthType.USERNAME_PASSWORD,
    var ikeUsername: String = "",
    var ikePassword: String = "",
    var ikePsk: String = "",
    // ---- L2TP / PPP (MikroTik و سایر سرورهای قدیمی) ----
    // «host:port» هم پذیرفته می‌شود؛ پیش‌فرض پورت ۱۷۰۱ است
    var l2tpServer: String = "",
    var l2tpUsername: String = "",
    var l2tpPassword: String = "",
    // رمز چالش تانل L2TP (فقط برای سرورهایی که secret تانل دارند؛ MikroTik ندارد)
    var l2tpSecret: String = "",
    var createdAt: Long = System.currentTimeMillis()
) {

    /** خلاصه‌ای برای نمایش در لیست */
    fun summary(): String = when (type) {
        ProfileType.WIREGUARD -> {
            val endpoint = Regex("(?i)^\\s*Endpoint\\s*=\\s*(.+)$", RegexOption.MULTILINE)
                .find(wgConfigText)?.groupValues?.get(1)?.trim()
            endpoint ?: "WireGuard"
        }
        ProfileType.IKEV2 -> ikeServer.ifBlank { "IKEv2/IPSec" }
        ProfileType.L2TP -> l2tpServer.ifBlank { "L2TP" }
    }

    /**
     * تولید نام تانل سازگار با قاعده کتابخانه WireGuard:
     * الگوی [a-zA-Z0-9_=+.-]{1,15}
     * با افزودن ۴ کاراکتر آخر id، پروفایل‌های هم‌نام نیز متمایز می‌مانند.
     */
    fun tunnelName(): String {
        val base = name.replace(Regex("[^a-zA-Z0-9_=+.-]"), "_").take(10)
        val seed = id.replace("-", "").takeLast(4)
        val candidate = if (base.isBlank()) "sl-$seed" else "$base-$seed"
        return candidate.take(15)
    }
}
