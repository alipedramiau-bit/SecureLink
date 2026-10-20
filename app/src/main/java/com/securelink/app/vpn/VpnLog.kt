package com.securelink.app.vpn

import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * گزارش رویدادهای VPN در حافظه (ring buffer) برای عیب‌یابی روی خودِ گوشی.
 *
 * هدف: کاربر بدون نیاز به کامپیوتر و adb بتواند علت قطع‌شدن اتصال را ببیند
 * و گزارش را کپی/اشتراک‌گذاری کند.
 *
 * کاملاً Kotlin خالص است (بدون وابستگی به android.util.Log) تا در تست‌های
 * واحد JVM هم قابل استفاده باشد.
 */
object VpnLog {

    /** بیشترین تعداد خطوط نگه‌داشته‌شده در حافظه */
    const val MAX_LINES = 800

    private const val TS_FORMAT = "HH:mm:ss.SSS"

    private val lock = Any()
    private val lines = ArrayDeque<String>(MAX_LINES)
    private val tsFormat = SimpleDateFormat(TS_FORMAT, Locale.US)

    /** شمارنده نسخه — با هر تغییر افزایش می‌یابد؛ UI برای refresh ارزان از آن استفاده می‌کند */
    @Volatile
    var version: Long = 0
        private set

    /** آخرین علت قطع‌شدن L2TP (برای نمایش در UI) */
    @Volatile
    var lastL2tpError: String? = null
        private set

    /** زمان آخرین علت قطع‌شدن (epoch ms)؛ ۰ یعنی هنوز چیزی ثبت نشده */
    @Volatile
    var lastL2tpErrorAt: Long = 0
        private set

    /** یک خط گزارش با مُهر زمانی ثبت می‌کند */
    fun log(tag: String, message: String) {
        // SimpleDateFormat غیر Thread-safe است — کل قالب‌سازی داخل قفل انجام می‌شود
        val line = synchronized(lock) {
            val l = "${tsFormat.format(Date())} $tag: ${message.replace('\n', ' ')}"
            if (lines.size >= MAX_LINES) lines.removeFirst()
            lines.addLast(l)
            l
        }
        version++
    }

    /** ثبت علت قطع‌شدن L2TP (هم به گزارش می‌رود هم برای UI نگه داشته می‌شود) */
    fun l2tpError(reason: String?) {
        val r = reason?.takeIf { it.isNotBlank() } ?: "دلیل نامشخص"
        lastL2tpError = r
        lastL2tpErrorAt = System.currentTimeMillis()
        log("L2TP", "قطع شد: $r")
    }

    /** محتوای کامل گزارش به‌صورت متن */
    fun snapshot(): String = synchronized(lock) { lines.joinToString("\n") }

    /** تعداد خطوط فعلی */
    fun lineCount(): Int = synchronized(lock) { lines.size }

    /** پاک‌کردن گزارش */
    fun clear() {
        synchronized(lock) { lines.clear() }
        lastL2tpError = null
        lastL2tpErrorAt = 0
        version++
    }
}
