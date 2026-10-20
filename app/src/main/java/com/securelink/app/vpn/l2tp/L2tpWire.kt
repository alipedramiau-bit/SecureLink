package com.securelink.app.vpn.l2tp

/**
 * کدک سطح سیم برای L2TPv2 (RFC 2661) — هدر بسته‌ها و AVP ها — و فریم‌های PPP.
 * همه اعداد چندبایتی Big-Endian هستند.
 */
internal object L2tpWire {

    // ---- ثابت‌های هدر ----
    const val FLAG_TYPE = 0x8000       // T: 1=کنترل، 0=داده
    const val FLAG_LENGTH = 0x4000     // L: فیلد Length موجود است
    const val FLAG_SEQ = 0x0800        // S: فیلدهای Ns/Nr موجودند
    const val FLAG_OFFSET = 0x0200     // O: فیلد Offset Size موجود است
    const val FLAG_PRIORITY = 0x0100   // P
    const val VERSION = 0x0002         // L2TPv2

    const val DEFAULT_PORT = 1701

    // ---- انواع پیام کنترلی (مقدار AVP نوع ۰) ----
    const val MSG_SCCRQ = 1
    const val MSG_SCCRP = 2
    const val MSG_SCCCN = 3
    const val MSG_STOP_CCN = 4
    const val MSG_HELLO = 6
    const val MSG_OCRQ = 7
    const val MSG_OCRP = 8
    const val MSG_OCCN = 9
    const val MSG_ICRQ = 10
    const val MSG_ICRP = 11
    const val MSG_ICCN = 12
    const val MSG_CDN = 14

    // ---- شماره AVP ها (RFC 2661 §10.1) ----
    const val AVP_MESSAGE_TYPE = 0
    const val AVP_RESULT_CODE = 1
    const val AVP_PROTOCOL_VERSION = 2
    const val AVP_FRAMING_CAPABILITIES = 3
    const val AVP_BEARER_CAPABILITIES = 4
    const val AVP_FIRMWARE_REVISION = 6
    const val AVP_HOST_NAME = 7
    const val AVP_VENDOR_NAME = 8
    const val AVP_ASSIGNED_TUNNEL_ID = 9
    const val AVP_RECEIVE_WINDOW_SIZE = 10
    const val AVP_CHALLENGE = 11
    const val AVP_CHALLENGE_RESPONSE = 13
    const val AVP_ASSIGNED_SESSION_ID = 14
    const val AVP_CALL_SERIAL_NUMBER = 15
    const val AVP_BEARER_TYPE = 18
    const val AVP_FRAMING_TYPE = 19
    const val AVP_TX_CONNECT_SPEED = 24
    const val AVP_RX_CONNECT_SPEED = 38
    const val AVP_SEQUENCING_REQUIRED = 39

    // ---- پروتکل‌های PPP (RFC 1661) ----
    const val PPP_IPV4 = 0x0021
    const val PPP_IPV6 = 0x0057
    const val PPP_LCP = 0xC021
    const val PPP_PAP = 0xC023
    const val PPP_CHAP = 0xC223
    const val PPP_IPCP = 0x8021

    // ---- کدهای بسته‌های کنترلی LCP/IPCP ----
    const val CODE_CONFIGURE_REQUEST = 1
    const val CODE_CONFIGURE_ACK = 2
    const val CODE_CONFIGURE_NAK = 3
    const val CODE_CONFIGURE_REJECT = 4
    const val CODE_TERMINATE_REQUEST = 5
    const val CODE_TERMINATE_ACK = 6
    const val CODE_ECHO_REQUEST = 9
    const val CODE_ECHO_REPLY = 10

    // ---- گزینه‌های LCP ----
    const val LCP_OPT_MRU = 1
    const val LCP_OPT_AUTH = 3
    const val LCP_OPT_MAGIC = 5

    // ---- گزینه‌های IPCP ----
    const val IPCP_OPT_IP_ADDRESS = 3
    const val IPCP_OPT_PRIMARY_DNS = 129
    const val IPCP_OPT_SECONDARY_DNS = 131

    // ---- الگوریتم‌های احراز هویت ----
    const val AUTH_PAP = 0xC023
    const val AUTH_CHAP_MD5 = 0xC223_05
    const val AUTH_MSCHAP1 = 0xC223_80
    const val AUTH_MSCHAP2 = 0xC223_81

    // ------------------------------------------------------------------
    // AVP
    // ------------------------------------------------------------------

    /** ساخت یک AVP کامل؛ Message-Type همیشه باید اولین AVP باشد. */
    fun avp(type: Int, value: ByteArray, mandatory: Boolean): ByteArray {
        val len = 6 + value.size
        val flags = (if (mandatory) 0x8000 else 0) or (len and 0x03FF)
        val out = ByteArray(len)
        out[0] = (flags ushr 8).toByte()
        out[1] = flags.toByte()
        // Vendor ID = 0
        out[4] = (type ushr 8).toByte()
        out[5] = type.toByte()
        System.arraycopy(value, 0, out, 6, value.size)
        return out
    }

    fun avpU16(type: Int, value: Int, mandatory: Boolean = true): ByteArray =
        avp(type, byteArrayOf((value ushr 8).toByte(), value.toByte()), mandatory)

    fun avpU32(type: Int, value: Long, mandatory: Boolean = true): ByteArray = avp(
        type,
        byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()),
        mandatory
    )

    /** AVP حاوی متن (Host Name / Vendor Name). */
    fun avpText(type: Int, text: String, mandatory: Boolean = true): ByteArray =
        avp(type, text.toByteArray(Charsets.US_ASCII), mandatory)

    /**
     * تجزیه AVPهای یک پیام کنترلی (بعد از هدر ۱۶ بایتی).
     * خروجی: فهرست (type, mandatory, value) به ترتیب سیم.
     * AVP مخفی (H=1) ارزش قابل رمزگشایی ندارد و فقط طولش رد می‌شود.
     */
    fun parseAvps(buf: ByteArray, offset: Int, end: Int): List<Avp> {
        val list = ArrayList<Avp>()
        var i = offset
        while (i + 6 <= end) {
            val flags = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            val mandatory = flags and 0x8000 != 0
            val hidden = flags and 0x4000 != 0
            val len = flags and 0x03FF
            if (len < 6 || i + len > end) break   // خراب — جایی که هست متوقف شو
            val type = ((buf[i + 4].toInt() and 0xFF) shl 8) or (buf[i + 5].toInt() and 0xFF)
            val value = if (hidden) ByteArray(0) else buf.copyOfRange(i + 6, i + len)
            list.add(Avp(type, mandatory, hidden, value))
            i += len
        }
        return list
    }

    data class Avp(val type: Int, val mandatory: Boolean, val hidden: Boolean, val value: ByteArray) {
        fun u16(): Int = ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
        fun u32(): Long {
            var v = 0L
            for (j in 0 until 4) v = (v shl 8) or (value[j].toLong() and 0xFF)
            return v
        }
    }

    fun findAvp(avps: List<Avp>, type: Int): Avp? = avps.firstOrNull { it.type == type }

    // ------------------------------------------------------------------
    // هدر کنترل / داده
    // ------------------------------------------------------------------

    /**
     * ساخت بسته کنترلی کامل (T=1, L=1, S=1).
     * هدر کنترل = ۱۲ بایت: Flags(2) + Length(2) + TunnelID(2) + SessionID(2) + Ns(2) + Nr(2)
     * tunnelId شناسه گیرنده است (قبل از دریافت SCCRP صفر می‌ماند). ZLB با avpBytes خالی.
     */
    fun buildControl(
        tunnelId: Int,
        sessionId: Int,
        ns: Int,
        nr: Int,
        avpBytes: ByteArray
    ): ByteArray {
        val length = 12 + avpBytes.size
        val out = ByteArray(length)
        out[0] = ((FLAG_TYPE or FLAG_LENGTH or FLAG_SEQ or VERSION) ushr 8).toByte()
        out[1] = (FLAG_TYPE or FLAG_LENGTH or FLAG_SEQ or VERSION).toByte()
        putU16(out, 2, length)
        putU16(out, 4, tunnelId)
        putU16(out, 6, sessionId)
        putU16(out, 8, ns)
        putU16(out, 10, nr)
        System.arraycopy(avpBytes, 0, out, 12, avpBytes.size)
        return out
    }

    /**
     * بسته داده L2TP.
     *
     * حالت پیش‌فرض: T=0, L=1, بدون توالی (هدر ۸ بایتی، Flags=0x4002).
     * اگر sequence >= 0 باشد (وقتی سرور AVP «Sequencing Required» فرستاده — RFC 2661 §4.4.6)،
     * S=1 هم می‌گذاریم (هدر ۱۲ بایتی، Flags=0x4802) و Ns=sequence و Nr=0
     * (طبق RFC 2661 §3.1 مقدار Nr در بسته‌های داده هنگام دریافت باید نادیده گرفته شود).
     * فضای شماره توالی داده، مستقل از فضای کنترل است (RFC 2661 §5.4).
     */
    fun buildData(tunnelId: Int, sessionId: Int, payload: ByteArray, sequence: Int = -1): ByteArray {
        val sequenced = sequence >= 0
        val length = (if (sequenced) 12 else 8) + payload.size
        val out = ByteArray(length)
        val flags = FLAG_LENGTH or VERSION or (if (sequenced) FLAG_SEQ else 0)
        out[0] = (flags ushr 8).toByte()
        out[1] = flags.toByte()
        putU16(out, 2, length)
        putU16(out, 4, tunnelId)
        putU16(out, 6, sessionId)
        if (sequenced) {
            putU16(out, 8, sequence)
            putU16(out, 10, 0)
        }
        System.arraycopy(payload, 0, out, if (sequenced) 12 else 8, payload.size)
        return out
    }

    data class ParsedPacket(
        val isControl: Boolean,
        val tunnelId: Int,
        val sessionId: Int,
        val ns: Int,
        val nr: Int,
        val payloadOffset: Int,   // شروع AVP یا بار PPP
        val payloadEnd: Int
    )

    /** تجزیه هدر L2TP؛ در صورت Ver != 2 یا طول ناکافی null برمی‌گردد. */
    fun parse(buf: ByteArray, length: Int): ParsedPacket? {
        if (length < 6) return null
        val flags = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
        if (flags and 0x000F != VERSION) return null
        val isControl = flags and FLAG_TYPE != 0
        val hasLength = flags and FLAG_LENGTH != 0
        val hasSeq = flags and FLAG_SEQ != 0
        val hasOffset = flags and FLAG_OFFSET != 0

        var i = 2
        if (hasLength) {
            if (length < 4) return null
            i += 2
        }
        if (i + 4 > length) return null
        val tunnelId = u16(buf, i); i += 2
        val sessionId = u16(buf, i); i += 2
        var ns = 0
        var nr = 0
        if (hasSeq) {
            if (i + 4 > length) return null
            ns = u16(buf, i); i += 2
            nr = u16(buf, i); i += 2
        }
        if (hasOffset) {
            if (i + 2 > length) return null
            val offsetSize = u16(buf, i); i += 2 + offsetSize
        }
        if (i > length) return null
        return ParsedPacket(isControl, tunnelId, sessionId, ns, nr, i, length)
    }

    // ------------------------------------------------------------------
    // فریم‌های PPP
    // ------------------------------------------------------------------

    /** فریم PPP کامل با آدرس/کنترل (ACFC توافق نمی‌شود): FF 03 ‖ Protocol ‖ payload. */
    fun pppFrame(protocol: Int, payload: ByteArray, payloadOffset: Int = 0, payloadLen: Int = payload.size - payloadOffset): ByteArray {
        val out = ByteArray(4 + payloadLen)
        out[0] = 0xFF.toByte()
        out[1] = 0x03.toByte()
        out[2] = (protocol ushr 8).toByte()
        out[3] = protocol.toByte()
        System.arraycopy(payload, payloadOffset, out, 4, payloadLen)
        return out
    }

    /** بسته کنترلی LCP/IPCP/CHAP/PAP: Code ‖ ID ‖ Length ‖ Data. */
    fun pppControlPacket(protocol: Int, code: Int, id: Int, data: ByteArray): ByteArray {
        val len = 4 + data.size
        val data2 = ByteArray(4 + data.size)
        data2[0] = code.toByte()
        data2[1] = id.toByte()
        putU16(data2, 2, len)
        System.arraycopy(data, 0, data2, 4, data.size)
        return pppFrame(protocol, data2)
    }

    data class PppPacket(val code: Int, val id: Int, val data: ByteArray)

    /** تجزیه یک فریم PPP (پس از حذف هدر L2TP). خروجی: (protocol, packet). */
    fun parsePpp(frame: ByteArray, offset: Int, end: Int): Pair<Int, PppPacket>? {
        var i = offset
        if (i + 2 > end) return null
        if (frame[i] == 0xFF.toByte() && frame[i + 1] == 0x03.toByte()) i += 2
        if (i + 2 > end) return null
        var protocol = ((frame[i].toInt() and 0xFF) shl 8) or (frame[i + 1].toInt() and 0xFF)
        i += 2
        // تحمل PFC سمت سرور: اگر پروتکل شناخته نشد و بایت اول معتبر بود، تک‌بایتی بخوان
        if (protocol !in KNOWN_PROTOCOLS) {
            val first = (protocol ushr 8) and 0xFF
            if (first == 0x21 || first == 0x57) {
                protocol = first
                i -= 1
            } else {
                return null
            }
        }
        if (i + 4 > end) return null
        val code = frame[i].toInt() and 0xFF
        val id = frame[i + 1].toInt() and 0xFF
        val len = u16(frame, i + 2)
        if (len < 4 || i + len > end) {
            // برخی سرورها Length را کوتاه می‌نویسند؛ تا انتهای فریم بخوان
            return Pair(protocol, PppPacket(code, id, frame.copyOfRange(i + 4, end)))
        }
        return Pair(protocol, PppPacket(code, id, frame.copyOfRange(i + 4, i + len)))
    }

    private val KNOWN_PROTOCOLS = setOf(
        PPP_IPV4, PPP_IPV6, PPP_LCP, PPP_PAP, PPP_CHAP, PPP_IPCP,
        0x80FD, 0xC029, 0xC027, 0x8235, 0x0035, 0x0281
    )

    // ------------------------------------------------------------------
    // گزینه‌های LCP / IPCP
    // ------------------------------------------------------------------

    fun optU16(type: Int, value: Int): ByteArray = byteArrayOf(type.toByte(), 4.toByte(), (value ushr 8).toByte(), value.toByte())

    fun optU32(type: Int, value: Long): ByteArray = byteArrayOf(
        type.toByte(), 6.toByte(),
        (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()
    )

    /** گزینه Auth-Protocol؛ برای CHAP سه بایت است. */
    fun optAuth(algorithm: Int): ByteArray = when (algorithm) {
        AUTH_PAP -> byteArrayOf(LCP_OPT_AUTH.toByte(), 4, 0xC0.toByte(), 0x23.toByte())
        else -> {
            val chapAlg = (algorithm and 0xFF).toByte()
            byteArrayOf(LCP_OPT_AUTH.toByte(), 5, 0xC2.toByte(), 0x23.toByte(), chapAlg)
        }
    }

    /** فهرست گزینه‌ها از بدنه بسته کنترلی LCP/IPCP. */
    fun parseOptions(data: ByteArray): List<Opt> {
        val list = ArrayList<Opt>()
        var i = 0
        while (i + 2 <= data.size) {
            val type = data[i].toInt() and 0xFF
            val len = data[i + 1].toInt() and 0xFF
            if (len < 2 || i + len > data.size) break
            list.add(Opt(type, data.copyOfRange(i + 2, i + len)))
            i += len
        }
        return list
    }

    data class Opt(val type: Int, val value: ByteArray) {
        fun u16(): Int = ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
        fun u32(): Long {
            var v = 0L
            for (j in 0 until 4) v = (v shl 8) or (value[j].toLong() and 0xFF)
            return v
        }
        fun bytes(): ByteArray {
            val out = ByteArray(2 + value.size)
            out[0] = type.toByte()
            // طول کل گزینه = ۲ بایت سرآیند + طول مقدار (RFC 1661 §4)
            // باگ قبلی: value.size نوشته می‌شد و ACK/Reject سمت سرور خراب می‌شد
            out[1] = (2 + value.size).toByte()
            System.arraycopy(value, 0, out, 2, out.size - 2)
            return out
        }
    }

    /** گزینه IP (آدرس/DNS) — ۴ بایت. */
    fun optIp(type: Int, ip: Int): ByteArray {
        val out = ByteArray(6)
        out[0] = type.toByte()
        out[1] = 6
        out[2] = (ip ushr 24).toByte()
        out[3] = (ip ushr 16).toByte()
        out[4] = (ip ushr 8).toByte()
        out[5] = ip.toByte()
        return out
    }

    fun bytesToIp(b: ByteArray, offset: Int = 0): Int =
        ((b[offset].toInt() and 0xFF) shl 24) or
        ((b[offset + 1].toInt() and 0xFF) shl 16) or
        ((b[offset + 2].toInt() and 0xFF) shl 8) or
        (b[offset + 3].toInt() and 0xFF)

    fun ipToString(ip: Int): String =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    // ------------------------------------------------------------------
    // ابزار
    // ------------------------------------------------------------------

    fun putU16(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v ushr 8).toByte()
        buf[off + 1] = v.toByte()
    }

    fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
}
