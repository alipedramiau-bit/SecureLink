package com.securelink.app.vpn.l2tp

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.Random
import java.util.concurrent.atomic.AtomicBoolean

/**
 * کلاینت L2TPv2 خالص (RFC 2661) + PPP (RFC 1661) برای اتصال به سرورهای MikroTik RouterOS.
 *
 * جریان اتصال:
 *   SCCRQ → SCCRP → SCCCN  (برقراری تانل)
 *   ICRQ   → ICRP  → ICCN   (برقراری جلسه)
 *   LCP (MRU/Auth/Magic) → احراز هویت (MS-CHAPv2/v1/CHAP-MD5/PAP) → IPCP (IP + DNS)
 *   → ساخت تانل VpnService و پمپ بسته‌ها
 *
 * نکته امنیتی: این پیاده‌سازی «L2TP بدون IPsec» است؛ احراز هویت با MS-CHAPv2 انجام
 * می‌شود ولی ترافیک رمزنگاری نمی‌شود. سرور MikroTik باید use-ipsec=no داشته باشد (پیش‌فرض).
 *
 * توالی کانال کنترل مطابق RFC 2661 §5.8: پیام ZLB یک اسلات از فضای Ns مصرف نمی‌کند
 * (Ns پس از ارسال ZLB جلو نمی‌رود) و Nr ارسالی هرگز با Nsِ ZLB دریافتی جلو برده نمی‌شود.
 * نقض همین قانون باعث می‌شد سرور Hello/CDN/StopCCN را تکراری بپندارد و تانل پس از
 * چند ثانیه استفاده قطع شود.
 */
internal class L2tpClient(
    private val serverAddress: String,
    private val username: String,
    private val password: String,
    private val tunnelSecret: String,
    private val protector: (DatagramSocket) -> Boolean,
    private val tunProvider: TunProvider,
    private val callbacks: Callbacks,
    helloIntervalMs: Long = HELLO_INTERVAL_DEFAULT_MS,
    connectDeadlineMs: Long = CONNECT_DEADLINE_DEFAULT_MS
) {
    interface Callbacks {
        /** تغییر فاز — برای اعلان و لاگ. */
        fun onPhase(phase: String)
        /** پایان کار؛ error = null یعنی قطع عادی. */
        fun onClosed(error: String?)
    }

    /** تأمین رابط TUN — در اندروید با ParcelFileDescriptor و در تست با لوله درون‌حافظه‌ای. */
    fun interface TunProvider {
        fun open(config: TunConfig): TunHandle?
    }

    /** دسترسی ورودی/خروجی رابط TUN (بسته‌های IP خام). */
    interface TunHandle {
        /** بسته‌های دریافتی از شبکه — باید در TUN نوشته شوند. */
        val outputStream: OutputStream
        /** بسته‌های خروجی اپ — از TUN خوانده می‌شوند. */
        val inputStream: InputStream
        fun close()
    }

    data class TunConfig(val address: String, val dns1: String, val dns2: String, val mtu: Int)

    private enum class AuthMethod { NONE, PAP, CHAP_MD5, MSCHAP1, MSCHAP2 }

    private enum class Phase { TUNNEL_CONNECT, SESSION_CONNECT, LCP, AUTH, IPCP, CONNECTED, CLOSED }

    // ---- ثابت‌ها ----
    private val OUR_MRU = 1450            // MikroTik پیش‌فرض max-mru=1450
    private val TUN_MTU = 1400
    private val CONTROL_RETRY_MAX = 5
    private val PPP_RETRY_MAX = 10
    private val CONNECT_DEADLINE_MS = connectDeadlineMs
    private val HELLO_INTERVAL_MS = helloIntervalMs
    private val REMOTE_CR_GRACE_MS = 6_000L

    // ---- وضعیت کلی ----
    private val running = AtomicBoolean(false)
    private var phase = Phase.TUNNEL_CONNECT
    private var closedNotified = false
    private val startedAt = System.currentTimeMillis()
    private val random = Random(System.nanoTime())

    // ---- شبکه ----
    private var socket: DatagramSocket? = null
    private var serverInetAddress: InetAddress? = null
    private var serverPort = L2tpWire.DEFAULT_PORT

    // ---- تانل L2TP ----
    private var ourTunnelId = random.nextInt(0xFFFE) + 1
    private var peerTunnelId = 0
    private var ourSessionId = random.nextInt(0xFFFE) + 1
    private var peerSessionId = 0
    private var nsOut = 0
    private var nrIn = 0
    private var callSerial = random.nextInt(0xFFFF)
    private var sessionEstablished = false
    private var lastInboundControlAt = System.currentTimeMillis()
    private var lastHelloSentAt = 0L
    private var lcpAckedAt = 0L
    private var ipcpAckedAt = 0L
    private var authStartAt = 0L

    private class Pending(val ns: Int, val bytes: ByteArray) {
        var retries = 0
        var nextRetryAt = System.currentTimeMillis() + 1500
    }
    private val pending = ArrayList<Pending>()

    // ---- وضعیت PPP ----
    private var magic = random.nextInt().let { if (it == 0) 0x5E0F1A6D else it }
    private var proposedAuth = L2tpWire.AUTH_MSCHAP2
    private var requiredAuth: AuthMethod = AuthMethod.NONE
    private var authDecided = false
    private var authDone = false

    private var lcpReqId = random.nextInt(0xFF)
    private var lcpConfReq: ByteArray? = null
    private var lcpReqRetries = 0
    private var lcpReqSentAt = 0L
    private var lcpLocalAcked = false
    private var lcpRemoteAcked = false
    private var lcpUpAt = 0L

    private var papReqId = random.nextInt(0xFF)

    private var chapIsV2 = false
    private var chapServerChallenge = ByteArray(0)
    private var chapPeerChallenge = ByteArray(0)
    private var chapNtResponse = ByteArray(0)

    private var ipcpReqId = random.nextInt(0xFF)
    private var ipcpConfReq: ByteArray? = null
    private var ipcpReqRetries = 0
    private var ipcpReqSentAt = 0L
    private var ipcpLocalAcked = false
    private var ipcpRemoteAcked = false
    private var ipcpUpAt = 0L

    private var includeDns1Opt = true
    private var includeDns2Opt = true
    private var negotiatedIp = 0
    private var dns1 = 0
    private var dns2 = 0

    // ---- تانل TUN ----
    private var tunHandle: TunHandle? = null
    private var tunThread: Thread? = null

    /** شماره توالیِ ZLB دریافتیِ اخیر — برای تحمل سرورهایی که (خلاف RFC) Nsِ ZLB را مصرف می‌کنند */
    private var zlbSeenAtNr = -1

    // ==================================================================
    // چرخه حیات
    // ==================================================================

    fun start() {
        if (!running.compareAndSet(false, true)) return
        Thread({
            try {
                runLoop()
            } catch (t: Throwable) {
                Log.e(TAG, "runLoop crashed", t)
                shutdownInternal(t.message ?: t.javaClass.simpleName)
            }
        }, "SecureLink-L2TP").start()
    }

    fun shutdown(reason: String?) {
        if (running.compareAndSet(true, false)) {
            shutdownInternal(reason)
        }
    }

    fun isRunning(): Boolean = running.get()

    // ==================================================================
    // حلقه اصلی
    // ==================================================================

    private fun runLoop() {
        setPhase(Phase.TUNNEL_CONNECT)
        serverPort = L2tpWire.DEFAULT_PORT
        val addr = resolveServer(serverAddress)
            ?: return shutdownInternal("آدرس سرور قابل حل نیست: $serverAddress")
        serverInetAddress = addr

        val sock = DatagramSocket()
        sock.reuseAddress = true
        // مهم: قبل از هر ترافیکی protect شود تا بسته‌های تانل داخل VPN خودمان گم نشوند
        if (!protector(sock)) {
            sock.close()
            return shutdownInternal("محافظت سوکت UDP از تانل ممکن نشد")
        }
        socket = sock

        // SCCRQ — شروع تانل
        sendControl(L2tpWire.MSG_SCCRQ, 0, sccrqAvps())

        val buf = ByteArray(4096)
        while (running.get()) {
            val now = System.currentTimeMillis()
            if (phase != Phase.CONNECTED && now - startedAt > CONNECT_DEADLINE_MS) {
                return shutdownInternal("زمان اتصال به پایان رسید؛ سرور پاسخ نداد")
            }
            checkTimers(now)
            if (!running.get()) break

            val timeout = computeSocketTimeout(now)
            try {
                sock.soTimeout = timeout
                val dp = DatagramPacket(buf, buf.size)
                sock.receive(dp)
                handleDatagram(buf, dp.length)
            } catch (_: SocketTimeoutException) {
                // تایمرها در بالای حلقه بررسی می‌شوند
            } catch (_: Exception) {
                if (running.get()) throw SocketClosed()
            }
        }
    }

    private class SocketClosed : Exception()

    private fun computeSocketTimeout(now: Long): Int {
        var next = Long.MAX_VALUE
        synchronized(pending) {
            for (p in pending) if (p.nextRetryAt < next) next = p.nextRetryAt
        }
        if (lcpConfReq != null && !lcpLocalAcked) next = minOf(next, lcpReqSentAt + 3000)
        if (ipcpConfReq != null && !ipcpLocalAcked) next = minOf(next, ipcpReqSentAt + 3000)
        if (phase == Phase.CONNECTED) next = minOf(next, lastHelloSentAt + HELLO_INTERVAL_MS)
        next = minOf(next, lastInboundControlAt + HELLO_INTERVAL_MS)
        val wait = if (next == Long.MAX_VALUE) 1000L else (next - now).coerceIn(50L, 1000L)
        return wait.toInt()
    }

    private fun checkTimers(now: Long) {
        // بازارسال بسته‌های کنترلی بی‌پاسخ
        synchronized(pending) {
            val it = pending.iterator()
            while (it.hasNext()) {
                val p = it.next()
                if (p.nextRetryAt <= now) {
                    p.retries++
                    if (p.retries > CONTROL_RETRY_MAX) {
                        it.remove()
                        shutdownInternal("سرور به پیام‌های کنترلی پاسخ نداد")
                        return
                    }
                    p.nextRetryAt = now + (1500L shl p.retries.coerceAtMost(3))
                    try {
                        socket?.send(DatagramPacket(p.bytes, p.bytes.size, serverInetAddress, serverPort))
                        Log.d(TAG, "retransmit control ns=${p.ns} retry=${p.retries}")
                    } catch (e: Exception) {
                        Log.w(TAG, "retransmit failed", e)
                    }
                }
            }
        }

        // بازارسال Configure-Request های PPP
        if (!lcpLocalAcked && lcpConfReq != null && now - lcpReqSentAt >= 3000) {
            lcpReqRetries++
            if (lcpReqRetries > PPP_RETRY_MAX) return shutdownInternal("سرور LCP را تأیید نکرد")
            lcpReqSentAt = now
            sendDatagram(lcpConfReq!!)
        }
        if (!ipcpLocalAcked && ipcpConfReq != null && now - ipcpReqSentAt >= 3000) {
            ipcpReqRetries++
            if (ipcpReqRetries > PPP_RETRY_MAX) return shutdownInternal("سرور IPCP را تأیید نکرد")
            ipcpReqSentAt = now
            sendDatagram(ipcpConfReq!!)
        }

        // HELLO — نگه‌داشتن تانل
        if (phase == Phase.CONNECTED && now - lastHelloSentAt >= HELLO_INTERVAL_MS &&
            now - lastInboundControlAt >= HELLO_INTERVAL_MS - 2000
        ) {
            lastHelloSentAt = now
            sendControl(L2tpWire.MSG_HELLO, 0, L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_HELLO))
        }
        if (now - lastInboundControlAt > 3 * HELLO_INTERVAL_MS + 15_000) {
            return shutdownInternal("ارتباط با سرور قطع شد (بدون پاسخ)")
        }

        // احراز هویت معطل مانده؟
        if (phase == Phase.AUTH && authStartAt > 0 && now - authStartAt > 40_000) {
            return shutdownInternal("سرور چالش احراز هویت نفرستاد")
        }
        // بخشنده بودن نسبت به سرورهایی که ConfReq خودشان را نمی‌فرستند
        if (!lcpRemoteAcked && lcpLocalAcked && now - lcpAckedAt > REMOTE_CR_GRACE_MS) {
            lcpRemoteAcked = true
            maybeLcpUp()
        }
        if (!ipcpRemoteAcked && ipcpLocalAcked && now - ipcpAckedAt > REMOTE_CR_GRACE_MS) {
            ipcpRemoteAcked = true
            maybeIpcpUp()
        }
    }

    // ==================================================================
    // دریافت و مسیریابی
    // ==================================================================

    private fun handleDatagram(buf: ByteArray, length: Int) {
        val pkt = L2tpWire.parse(buf, length) ?: return
        // اعتبارسنجی شناسه‌ها — نویز بسته‌های تونل‌های دیگر رد شود (بعد از تکمیل دست‌دهی)
        if (peerTunnelId != 0 && pkt.tunnelId != ourTunnelId) return
        if (!pkt.isControl && sessionEstablished && pkt.sessionId != ourSessionId) return
        if (pkt.isControl) {
            lastInboundControlAt = System.currentTimeMillis()
            val avps = L2tpWire.parseAvps(buf, pkt.payloadOffset, pkt.payloadEnd)
            val isZlb = avps.isEmpty()
            if (pkt.ns == nrIn) {
                if (isZlb) {
                    // RFC 2661 §5.8: «Ns پس از ZLB جلو نمی‌رود» — nrIn نباید جلو برود؛
                    // وگرنه پیام واقعی بعدی سرور (Hello/CDN/…) تکراری پنداشته شده و نادیده گرفته می‌شود.
                    zlbSeenAtNr = nrIn
                } else {
                    nrIn = (nrIn + 1) and 0xFFFF
                    zlbSeenAtNr = -1
                    processControl(avps)
                }
            } else if (isAhead(pkt.ns, nrIn)) {
                val tolerated = !isZlb &&
                    zlbSeenAtNr == nrIn &&
                    pkt.ns == ((nrIn + 1) and 0xFFFF)
                if (tolerated) {
                    // برخی سرورها (خلاف RFC) برای ZLB هم Ns مصرف می‌کنند — تحمل می‌شود
                    nrIn = (pkt.ns + 1) and 0xFFFF
                    zlbSeenAtNr = -1
                    processControl(avps)
                } else {
                    return   // شکاف واقعی — فرستنده بازارسال می‌کند (بدون ACK طبق RFC)
                }
            }
            // حذف بسته‌های تأییدشده با Nr (مقایسه چرخه‌ای؛ شامل ZLB دریافتی)
            synchronized(pending) {
                pending.removeAll { ((pkt.nr - it.ns) and 0xFFFF) in 1..0x7FFF }
            }
            sendZlb()
        } else {
            if (phase != Phase.CONNECTED && phase != Phase.IPCP && phase != Phase.AUTH && phase != Phase.LCP) return
            handlePppFrame(buf, pkt.payloadOffset, pkt.payloadEnd)
        }
    }

    /** آیا ns به‌صورت چرخه‌ای (modulo 65536) جلوتر از base است؟ */
    private fun isAhead(ns: Int, base: Int): Boolean =
        ((ns - base) and 0xFFFF) in 1..0x7FFF

    private fun processControl(avps: List<L2tpWire.Avp>) {
        val msgType = L2tpWire.findAvp(avps, L2tpWire.AVP_MESSAGE_TYPE)?.u16() ?: return
        when (msgType) {
            L2tpWire.MSG_SCCRP -> {
                if (phase != Phase.TUNNEL_CONNECT) return
                val protoVer = L2tpWire.findAvp(avps, L2tpWire.AVP_PROTOCOL_VERSION)?.u16() ?: 0x0100
                if ((protoVer ushr 8) != 1) {
                    return shutdownInternal("نسخه L2TP سرور (${(protoVer ushr 8)}.${protoVer and 0xFF}) پشتیبانی نمی‌شود")
                }
                peerTunnelId = L2tpWire.findAvp(avps, L2tpWire.AVP_ASSIGNED_TUNNEL_ID)?.u16() ?: 0
                if (peerTunnelId == 0) return shutdownInternal("سرور شناسه تانل را ارسال نکرد")
                // پاسخ به چالش سرور (در صورت وجود)
                val challenge = L2tpWire.findAvp(avps, L2tpWire.AVP_CHALLENGE)?.value
                val avps2 = ArrayList<ByteArray>()
                avps2.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_SCCCN))
                if (challenge != null && challenge.isNotEmpty()) {
                    val secret = tunnelSecret.toByteArray(Charsets.US_ASCII)
                    val resp = L2tpCrypto.l2tpChallengeResponse(L2tpWire.MSG_SCCCN, secret, challenge)
                    avps2.add(L2tpWire.avp(L2tpWire.AVP_CHALLENGE_RESPONSE, resp, true))
                }
                Log.i(TAG, "tunnel established (tid=$peerTunnelId)")
                sendControl(L2tpWire.MSG_SCCCN, 0, concatBytes(avps2))
                setPhase(Phase.SESSION_CONNECT)
                sendControl(L2tpWire.MSG_ICRQ, 0, icrqAvps())
            }
            L2tpWire.MSG_ICRP -> {
                if (phase != Phase.SESSION_CONNECT) return
                peerSessionId = L2tpWire.findAvp(avps, L2tpWire.AVP_ASSIGNED_SESSION_ID)?.u16() ?: 0
                if (peerSessionId == 0) return shutdownInternal("سرور شناسه جلسه را ارسال نکرد")
                Log.i(TAG, "session established (sid=$peerSessionId)")
                sendControl(L2tpWire.MSG_ICCN, peerSessionId, iccnAvps())
                sessionEstablished = true
                setPhase(Phase.LCP)
                sendLcpConfReq()
            }
            L2tpWire.MSG_STOP_CCN -> {
                val result = parseResultCode(L2tpWire.findAvp(avps, L2tpWire.AVP_RESULT_CODE))
                running.set(false)
                shutdownInternal(result?.second ?: "سرور تانل را بست")
            }
            L2tpWire.MSG_CDN -> {
                val result = parseResultCode(L2tpWire.findAvp(avps, L2tpWire.AVP_RESULT_CODE))
                running.set(false)
                shutdownInternal(result?.second ?: "سرور جلسه را بست")
            }
            L2tpWire.MSG_HELLO -> { /* با ZLB تأیید شد */ }
            else -> Log.d(TAG, "ignoring control message type=$msgType")
        }
    }

    /** (result, message) یا null */
    private fun parseResultCode(avp: L2tpWire.Avp?): Pair<Int, String>? {
        if (avp == null || avp.value.size < 2) return null
        val result = avp.u16()
        var message = "خطا $result"
        if (avp.value.size >= 6) {
            val msgLen = ((avp.value[4].toInt() and 0xFF) shl 8) or (avp.value[5].toInt() and 0xFF)
            if (msgLen > 0 && avp.value.size >= 6 + msgLen) {
                message = String(avp.value, 6, msgLen, Charsets.UTF_8)
            }
        }
        return Pair(result, message)
    }

    // ==================================================================
    // PPP
    // ==================================================================

    private fun handlePppFrame(buf: ByteArray, offset: Int, end: Int) {
        val parsed = L2tpWire.parsePpp(buf, offset, end) ?: return
        val (protocol, packet) = parsed
        when (protocol) {
            L2tpWire.PPP_IPV4 -> {
                val start = findIpv4Start(buf, offset, end)
                if (start >= 0) writeTun(buf, start, end - start)
            }
            L2tpWire.PPP_LCP -> handleLcp(packet)
            L2tpWire.PPP_IPCP -> handleIpcp(packet)
            L2tpWire.PPP_PAP -> handlePap(packet)
            L2tpWire.PPP_CHAP -> handleChap(packet)
            else -> Log.d(TAG, "ignoring PPP protocol ${Integer.toHexString(protocol)}")
        }
    }

    private fun findIpv4Start(buf: ByteArray, offset: Int, end: Int): Int {
        var i = offset
        if (i + 2 <= end && buf[i] == 0xFF.toByte() && buf[i + 1] == 0x03.toByte()) i += 2
        if (i + 2 > end) return -1
        val proto = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
        i += 2
        if (proto == L2tpWire.PPP_IPV4) return i
        if ((proto ushr 8) == 0x21) return i - 1   // PFC تک‌بایتی از سمت سرور
        return -1
    }

    private fun writeTun(buf: ByteArray, start: Int, len: Int) {
        if (start < 0 || len <= 0) return
        val out = tunHandle?.outputStream ?: return
        try {
            out.write(buf, start, len)
            out.flush()
        } catch (e: Exception) {
            Log.w(TAG, "tun write failed", e)
        }
    }

    // ---- LCP ----

    private fun sendLcpConfReq() {
        val opts = ArrayList<ByteArray>()
        opts.add(L2tpWire.optU16(L2tpWire.LCP_OPT_MRU, OUR_MRU))
        if (!authOptionRejected) opts.add(L2tpWire.optAuth(proposedAuth))
        if (!magicRejected) opts.add(L2tpWire.optU32(L2tpWire.LCP_OPT_MAGIC, magic.toLong() and 0xFFFFFFFFL))
        lcpReqId = (lcpReqId + 1) and 0xFF
        // فریم PPP باید داخل پیام داده L2TP کپسوله شود — ارسال فریم خام قابل پردازش نیست
        lcpConfReq = L2tpWire.buildData(
            peerTunnelId, peerSessionId,
            L2tpWire.pppControlPacket(L2tpWire.PPP_LCP, L2tpWire.CODE_CONFIGURE_REQUEST, lcpReqId, concatBytes(opts))
        )
        lcpReqRetries = 0
        lcpReqSentAt = System.currentTimeMillis()
        sendDatagram(lcpConfReq!!)
        Log.d(TAG, "LCP ConfReq sent (id=$lcpReqId)")
    }

    private var authOptionRejected = false
    private var magicRejected = false

    private fun handleLcp(p: L2tpWire.PppPacket) {
        when (p.code) {
            L2tpWire.CODE_CONFIGURE_ACK -> {
                if (p.id != lcpReqId) return
                lcpLocalAcked = true
                lcpAckedAt = System.currentTimeMillis()
                lcpUpAt = lcpAckedAt
                Log.i(TAG, "LCP ConfReq Acked")
                maybeLcpUp()
            }
            L2tpWire.CODE_CONFIGURE_NAK -> {
                if (p.id != lcpReqId) return
                for (opt in L2tpWire.parseOptions(p.data)) {
                    when (opt.type) {
                        L2tpWire.LCP_OPT_AUTH -> {
                            val algo = parseAuthOption(opt)
                            if (algo != null) {
                                proposedAuth = algo
                                authOptionRejected = false
                                Log.i(TAG, "server suggests auth=${Integer.toHexString(algo)}")
                            }
                        }
                        L2tpWire.LCP_OPT_MRU -> { /* همان MRU خودمان را نگه می‌داریم */ }
                    }
                }
                sendLcpConfReq()
            }
            L2tpWire.CODE_CONFIGURE_REJECT -> {
                if (p.id != lcpReqId) return
                for (opt in L2tpWire.parseOptions(p.data)) {
                    when (opt.type) {
                        L2tpWire.LCP_OPT_AUTH -> authOptionRejected = true
                        L2tpWire.LCP_OPT_MAGIC -> magicRejected = true
                    }
                }
                sendLcpConfReq()
            }
            L2tpWire.CODE_CONFIGURE_REQUEST -> handleRemoteConfReq(L2tpWire.PPP_LCP, p)
            L2tpWire.CODE_TERMINATE_REQUEST -> {
                sendPppControl(L2tpWire.PPP_LCP, L2tpWire.CODE_TERMINATE_ACK, p.id, ByteArray(0))
                shutdownInternal("سرور اتصال را پایان داد")
            }
            L2tpWire.CODE_ECHO_REQUEST -> {
                val body = ByteArray(4)
                L2tpWire.putU16(body, 0, (magic ushr 16) and 0xFFFF)
                L2tpWire.putU16(body, 2, magic and 0xFFFF)
                sendPppControl(L2tpWire.PPP_LCP, L2tpWire.CODE_ECHO_REPLY, p.id, body)
            }
            else -> Log.d(TAG, "LCP code=${p.code} ignored")
        }
    }

    /** گزینه Auth سمت سرور: یا باید بپذیریم یا با الگوریتم پشتیبانی‌شده Nak بدهیم. */
    private fun parseAuthOption(opt: L2tpWire.Opt): Int? = when {
        opt.value.size >= 2 && (opt.value[0].toInt() and 0xFF) == 0xC0 && (opt.value[1].toInt() and 0xFF) == 0x23 ->
            L2tpWire.AUTH_PAP
        opt.value.size >= 3 && (opt.value[0].toInt() and 0xFF) == 0xC2 && (opt.value[1].toInt() and 0xFF) == 0x23 ->
            when (opt.value[2].toInt() and 0xFF) {
                0x05 -> L2tpWire.AUTH_CHAP_MD5
                0x80 -> L2tpWire.AUTH_MSCHAP1
                0x81 -> L2tpWire.AUTH_MSCHAP2
                else -> null
            }
        else -> null
    }

    private fun handleRemoteConfReq(protocol: Int, p: L2tpWire.PppPacket) {
        val acks = ArrayList<ByteArray>()
        val naks = ArrayList<ByteArray>()
        val rejects = ArrayList<ByteArray>()
        var serverDns1 = 0
        var serverDns2 = 0
        for (opt in L2tpWire.parseOptions(p.data)) {
            when {
                protocol == L2tpWire.PPP_LCP && opt.type == L2tpWire.LCP_OPT_MRU -> acks.add(opt.bytes())
                protocol == L2tpWire.PPP_LCP && opt.type == L2tpWire.LCP_OPT_MAGIC -> acks.add(opt.bytes())
                protocol == L2tpWire.PPP_LCP && opt.type == L2tpWire.LCP_OPT_AUTH -> {
                    val algo = parseAuthOption(opt)
                    if (algo != null) {
                        acks.add(opt.bytes())
                        // اگر سرور الگوریتمی خواست، همان را انجام می‌دهیم
                        requiredAuth = when (algo) {
                            L2tpWire.AUTH_PAP -> AuthMethod.PAP
                            L2tpWire.AUTH_CHAP_MD5 -> AuthMethod.CHAP_MD5
                            L2tpWire.AUTH_MSCHAP1 -> AuthMethod.MSCHAP1
                            L2tpWire.AUTH_MSCHAP2 -> AuthMethod.MSCHAP2
                            else -> AuthMethod.NONE
                        }
                        authDecided = true
                    } else {
                        naks.add(L2tpWire.optAuth(L2tpWire.AUTH_MSCHAP2))
                    }
                }
                protocol == L2tpWire.PPP_IPCP && opt.type == L2tpWire.IPCP_OPT_IP_ADDRESS -> acks.add(opt.bytes())
                protocol == L2tpWire.PPP_IPCP && opt.type == L2tpWire.IPCP_OPT_PRIMARY_DNS -> {
                    if (opt.value.size == 4) serverDns1 = L2tpWire.bytesToIp(opt.value)
                    acks.add(opt.bytes())
                }
                protocol == L2tpWire.PPP_IPCP && opt.type == L2tpWire.IPCP_OPT_SECONDARY_DNS -> {
                    if (opt.value.size == 4) serverDns2 = L2tpWire.bytesToIp(opt.value)
                    acks.add(opt.bytes())
                }
                else -> rejects.add(opt.bytes())
            }
        }
        if (serverDns1 != 0 && dns1 == 0) dns1 = serverDns1
        if (serverDns2 != 0 && dns2 == 0) dns2 = serverDns2

        val data = when {
            rejects.isNotEmpty() -> concatBytes(rejects)
            naks.isNotEmpty() -> concatBytes(naks)
            else -> {
                if (protocol == L2tpWire.PPP_LCP) lcpRemoteAcked = true else ipcpRemoteAcked = true
                p.data   // Ack: گزینه‌های اصلی دست‌نخورده
            }
        }
        val code = when {
            rejects.isNotEmpty() -> L2tpWire.CODE_CONFIGURE_REJECT
            naks.isNotEmpty() -> L2tpWire.CODE_CONFIGURE_NAK
            else -> L2tpWire.CODE_CONFIGURE_ACK
        }
        sendPppControl(protocol, code, p.id, data)
        if (protocol == L2tpWire.PPP_LCP) maybeLcpUp() else maybeIpcpUp()
    }

    private fun maybeLcpUp() {
        if (!lcpLocalAcked || !lcpRemoteAcked) return
        if (phase != Phase.LCP && phase != Phase.AUTH) return
        lcpConfReq = null
        decideAuthMethod()
        if (requiredAuth == AuthMethod.NONE) {
            authDone = true
            setPhase(Phase.IPCP)
            sendIpcpConfReq()
        } else {
            authStartAt = System.currentTimeMillis()
            setPhase(Phase.AUTH)
            if (requiredAuth == AuthMethod.PAP) sendPapRequest()
            // CHAP منتظر چالش سرور می‌ماند
        }
    }

    private fun decideAuthMethod() {
        if (authDecided) return
        // از پیشنهاد خودمان (که Ack شد) نتیجه می‌گیریم
        requiredAuth = when (proposedAuth) {
            L2tpWire.AUTH_PAP -> AuthMethod.PAP
            L2tpWire.AUTH_CHAP_MD5 -> AuthMethod.CHAP_MD5
            L2tpWire.AUTH_MSCHAP1 -> AuthMethod.MSCHAP1
            else -> AuthMethod.MSCHAP2
        }
        authDecided = true
    }

    // ---- PAP ----

    private fun sendPapRequest() {
        val user = username.toByteArray(Charsets.UTF_8)
        val pass = password.toByteArray(Charsets.UTF_8)
        val data = ByteArray(2 + user.size + 2 + pass.size)
        var i = 0
        data[i++] = user.size.toByte()
        System.arraycopy(user, 0, data, i, user.size); i += user.size
        data[i++] = pass.size.toByte()
        System.arraycopy(pass, 0, data, i, pass.size)
        sendPppControl(L2tpWire.PPP_PAP, 1, papReqId, data)
        Log.d(TAG, "PAP Authenticate-Request sent")
    }

    private fun handlePap(p: L2tpWire.PppPacket) {
        when (p.code) {
            2 -> {   // Ack
                authDone = true
                setPhase(Phase.IPCP)
                sendIpcpConfReq()
            }
            3 -> shutdownInternal("احراز هویت ناموفق بود (PAP Nak)")
        }
    }

    // ---- CHAP ----

    private fun handleChap(p: L2tpWire.PppPacket) {
        when (p.code) {
            1 -> {   // Challenge
                if (p.data.isEmpty()) return
                val valueSize = p.data[0].toInt() and 0xFF
                if (valueSize == 0 || 1 + valueSize > p.data.size) return
                chapServerChallenge = p.data.copyOfRange(1, 1 + valueSize)
                val user = username
                val pass = password
                val responseValue: ByteArray = when {
                    // اگر سرور صراحتاً CHAP-MD5 خواسته، اولویت با آن است (چالش MD5 ممکن است ۸ بایتی هم باشد)
                    requiredAuth == AuthMethod.CHAP_MD5 -> {
                        chapIsV2 = false
                        requiredAuth = AuthMethod.CHAP_MD5
                        L2tpCrypto.chapMd5Response(p.id, pass.toByteArray(Charsets.UTF_8), chapServerChallenge)
                    }
                    valueSize == 16 && (requiredAuth == AuthMethod.MSCHAP2 || requiredAuth == AuthMethod.NONE) -> {
                        chapIsV2 = true
                        requiredAuth = AuthMethod.MSCHAP2
                        chapPeerChallenge = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
                        L2tpCrypto.buildMsChap2ResponseValue(chapServerChallenge, chapPeerChallenge, user, pass)
                    }
                    valueSize == 8 && (requiredAuth == AuthMethod.MSCHAP1 || requiredAuth == AuthMethod.NONE) -> {
                        chapIsV2 = false
                        requiredAuth = AuthMethod.MSCHAP1
                        L2tpCrypto.buildMsChap1ResponseValue(chapServerChallenge, pass)
                    }
                    else -> {
                        chapIsV2 = false
                        requiredAuth = AuthMethod.CHAP_MD5
                        L2tpCrypto.chapMd5Response(p.id, pass.toByteArray(Charsets.UTF_8), chapServerChallenge)
                    }
                }
                if (chapIsV2) chapNtResponse = responseValue.copyOfRange(24, 48)
                // پاسخ: Value-Size ‖ Value ‖ Name
                val name = user.toByteArray(Charsets.UTF_8)
                val body = ByteArray(1 + responseValue.size + name.size)
                body[0] = responseValue.size.toByte()
                System.arraycopy(responseValue, 0, body, 1, responseValue.size)
                System.arraycopy(name, 0, body, 1 + responseValue.size, name.size)
                sendPppControl(L2tpWire.PPP_CHAP, 2, p.id, body)
                Log.d(TAG, "CHAP Response sent (v2=$chapIsV2)")
            }
            3 -> {   // Success
                verifyChapSuccess(p)
                authDone = true
                Log.i(TAG, "authentication succeeded")
                setPhase(Phase.IPCP)
                sendIpcpConfReq()
            }
            4 -> {   // Failure
                val msg = String(p.data, Charsets.UTF_8)
                val cause = extractMsChapError(msg)
                shutdownInternal("احراز هویت ناموفق بود$cause")
            }
        }
    }

    private fun verifyChapSuccess(p: L2tpWire.PppPacket) {
        if (!chapIsV2) return
        val msg = String(p.data, Charsets.UTF_8)
        val sIdx = msg.indexOf("S=")
        if (sIdx < 0) return
        val hex = msg.substring(sIdx + 2).take(40)
        try {
            val expected = L2tpCrypto.generateAuthenticatorResponse(
                password, chapNtResponse, chapPeerChallenge,
                chapServerChallenge, username
            )
            // chapPeerChallenge در buildMsChap2ResponseValue ساخته می‌شود؛ آنجا ذخیره کن
            val expectedHex = expected.joinToString("") { String.format("%02X", it) }
            if (!hex.equals(expectedHex, ignoreCase = true)) {
                Log.w(TAG, "Authenticator Response mismatch — server may be misbehaving")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "auth response check failed", t)
        }
    }

    private fun extractMsChapError(msg: String): String {
        val eIdx = msg.indexOf("E=")
        if (eIdx >= 0) {
            val num = msg.substring(eIdx + 2).takeWhile { it.isDigit() }
            return when (num) {
                "646" -> " (رمز عبور منقضی شده)"
                "647" -> " (حساب غیرفعال است)"
                "648" -> " (رمز عبور منقضی شده)"
                "649" -> " (حساب بدون مجوز)"
                "691" -> " (نام کاربری یا رمز عبور اشتباه است)"
                else -> " (خطای احراز هویت $num)"
            }
        }
        return if (msg.isNotBlank()) " — ${msg.take(80)}" else ""
    }

    // ---- IPCP ----

    private fun sendIpcpConfReq() {
        val opts = ArrayList<ByteArray>()
        opts.add(L2tpWire.optIp(L2tpWire.IPCP_OPT_IP_ADDRESS, negotiatedIp))
        if (includeDns1Opt) opts.add(L2tpWire.optIp(L2tpWire.IPCP_OPT_PRIMARY_DNS, dns1))
        if (includeDns2Opt) opts.add(L2tpWire.optIp(L2tpWire.IPCP_OPT_SECONDARY_DNS, dns2))
        ipcpReqId = (ipcpReqId + 1) and 0xFF
        // کپسوله‌سازی در L2TP — همان اصلاح LCP
        ipcpConfReq = L2tpWire.buildData(
            peerTunnelId, peerSessionId,
            L2tpWire.pppControlPacket(L2tpWire.PPP_IPCP, L2tpWire.CODE_CONFIGURE_REQUEST, ipcpReqId, concatBytes(opts))
        )
        ipcpReqRetries = 0
        ipcpReqSentAt = System.currentTimeMillis()
        sendDatagram(ipcpConfReq!!)
        Log.d(TAG, "IPCP ConfReq sent (id=$ipcpReqId)")
    }

    private fun handleIpcp(p: L2tpWire.PppPacket) {
        when (p.code) {
            L2tpWire.CODE_CONFIGURE_ACK -> {
                if (p.id != ipcpReqId) return
                for (opt in L2tpWire.parseOptions(p.data)) {
                    if (opt.type == L2tpWire.IPCP_OPT_IP_ADDRESS && opt.value.size == 4) {
                        negotiatedIp = L2tpWire.bytesToIp(opt.value)
                    }
                    if (opt.type == L2tpWire.IPCP_OPT_PRIMARY_DNS && opt.value.size == 4 && dns1 == 0) {
                        dns1 = L2tpWire.bytesToIp(opt.value)
                    }
                    if (opt.type == L2tpWire.IPCP_OPT_SECONDARY_DNS && opt.value.size == 4 && dns2 == 0) {
                        dns2 = L2tpWire.bytesToIp(opt.value)
                    }
                }
                ipcpLocalAcked = true
                ipcpAckedAt = System.currentTimeMillis()
                ipcpUpAt = ipcpAckedAt
                Log.i(TAG, "IPCP ConfReq Acked (ip=${L2tpWire.ipToString(negotiatedIp)})")
                maybeIpcpUp()
            }
            L2tpWire.CODE_CONFIGURE_NAK -> {
                if (p.id != ipcpReqId) return
                for (opt in L2tpWire.parseOptions(p.data)) {
                    val v = if (opt.value.size == 4) L2tpWire.bytesToIp(opt.value) else 0
                    when (opt.type) {
                        L2tpWire.IPCP_OPT_IP_ADDRESS -> negotiatedIp = v
                        L2tpWire.IPCP_OPT_PRIMARY_DNS -> { dns1 = v; if (v == 0) includeDns1Opt = false }
                        L2tpWire.IPCP_OPT_SECONDARY_DNS -> { dns2 = v; if (v == 0) includeDns2Opt = false }
                    }
                }
                sendIpcpConfReq()
            }
            L2tpWire.CODE_CONFIGURE_REJECT -> {
                if (p.id != ipcpReqId) return
                for (opt in L2tpWire.parseOptions(p.data)) {
                    when (opt.type) {
                        L2tpWire.IPCP_OPT_PRIMARY_DNS -> includeDns1Opt = false
                        L2tpWire.IPCP_OPT_SECONDARY_DNS -> includeDns2Opt = false
                    }
                }
                sendIpcpConfReq()
            }
            L2tpWire.CODE_CONFIGURE_REQUEST -> handleRemoteConfReq(L2tpWire.PPP_IPCP, p)
            L2tpWire.CODE_TERMINATE_REQUEST -> {
                sendPppControl(L2tpWire.PPP_IPCP, L2tpWire.CODE_TERMINATE_ACK, p.id, ByteArray(0))
                shutdownInternal("سرور اتصال را پایان داد")
            }
            else -> Log.d(TAG, "IPCP code=${p.code} ignored")
        }
    }

    private fun maybeIpcpUp() {
        if (!ipcpLocalAcked || !ipcpRemoteAcked || phase == Phase.CONNECTED) return
        if (negotiatedIp == 0) return   // هنوز آدرس نگرفته‌ایم
        ipcpConfReq = null
        startTun()
    }

    // ==================================================================
    // تانل TUN
    // ==================================================================

    private fun startTun() {
        val ip = L2tpWire.ipToString(negotiatedIp)
        val d1 = if (dns1 != 0) L2tpWire.ipToString(dns1) else "8.8.8.8"
        val d2 = if (dns2 != 0) L2tpWire.ipToString(dns2) else "1.1.1.1"
        Log.i(TAG, "bringing up tun: ip=$ip dns=$d1,$d2 mtu=$TUN_MTU")
        val handle = tunProvider.open(TunConfig(ip, d1, d2, TUN_MTU))
        if (handle == null) return shutdownInternal("ایجاد رابط تانل ممکن نشد")
        tunHandle = handle
        setPhase(Phase.CONNECTED)

        tunThread = Thread({
            try {
                val input = handle.inputStream
                val buf = ByteArray(4096)
                while (running.get()) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    if (n < 20) continue
                    val frame = L2tpWire.pppFrame(L2tpWire.PPP_IPV4, buf, 0, n)
                    val packet = L2tpWire.buildData(peerTunnelId, peerSessionId, frame)
                    sendDatagram(packet)
                }
            } catch (_: Exception) {
                // خروج از حلقه — پایین در finally بررسی می‌شود
            } finally {
                // خطای ورودی/خروجی TUN نباید به «اتصال زامبی» برسد
                if (running.get()) shutdownInternal("خطای ورودی/خروجی رابط تانل")
            }
        }, "SecureLink-L2TP-Tun")
        tunThread?.start()
    }

    // ==================================================================
    // ارسال
    // ==================================================================

    private fun sendDatagram(bytes: ByteArray) {
        val sock = socket ?: return
        try {
            sock.send(DatagramPacket(bytes, bytes.size, serverInetAddress, serverPort))
        } catch (e: Exception) {
            Log.w(TAG, "send failed", e)
        }
    }

    /** ارسال پیام کنترلی واقعی (Ns مصرف می‌شود) و ثبت برای بازارسال. */
    private fun sendControl(messageType: Int, sessionId: Int, avpBytes: ByteArray) {
        val ns = nsOut
        val packet = L2tpWire.buildControl(peerTunnelId, sessionId, ns, nrIn, avpBytes)
        nsOut = (nsOut + 1) and 0xFFFF
        synchronized(pending) { pending.add(Pending(ns, packet)) }
        sendDatagram(packet)
        Log.d(TAG, "control sent type=$messageType ns=$ns")
    }

    /** ZLB — تأیید دریافت بدون مصرف Ns. */
    private fun sendZlb() {
        val packet = L2tpWire.buildControl(peerTunnelId, 0, nsOut, nrIn, ByteArray(0))
        sendDatagram(packet)
    }

    private fun sendPppControl(protocol: Int, code: Int, id: Int, data: ByteArray) {
        val frame = L2tpWire.pppControlPacket(protocol, code, id, data)
        val packet = L2tpWire.buildData(peerTunnelId, peerSessionId, frame)
        sendDatagram(packet)
    }

    // ==================================================================
    // AVP های پیام‌ها
    // ==================================================================

    private fun sccrqAvps(): ByteArray {
        val list = ArrayList<ByteArray>()
        list.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_SCCRQ))
        list.add(L2tpWire.avpU16(L2tpWire.AVP_PROTOCOL_VERSION, 0x0100))
        list.add(L2tpWire.avpText(L2tpWire.AVP_HOST_NAME, "SecureLink"))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_FRAMING_CAPABILITIES, 0x00000003))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_BEARER_CAPABILITIES, 0x00000003))
        list.add(L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_TUNNEL_ID, ourTunnelId))
        list.add(L2tpWire.avpU16(L2tpWire.AVP_RECEIVE_WINDOW_SIZE, 4))
        list.add(L2tpWire.avpText(L2tpWire.AVP_VENDOR_NAME, "SecureLink", false))
        return concatBytes(list)
    }

    private fun icrqAvps(): ByteArray {
        val list = ArrayList<ByteArray>()
        list.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_ICRQ))
        list.add(L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_SESSION_ID, ourSessionId))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_CALL_SERIAL_NUMBER, callSerial.toLong() and 0xFFFFFFFFL))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_BEARER_TYPE, 0x00000003))
        return concatBytes(list)
    }

    private fun iccnAvps(): ByteArray {
        val list = ArrayList<ByteArray>()
        list.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_ICCN))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_TX_CONNECT_SPEED, 100_000_000))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_FRAMING_TYPE, 0x00000003))
        list.add(L2tpWire.avpU32(L2tpWire.AVP_RX_CONNECT_SPEED, 100_000_000, false))
        return concatBytes(list)
    }

    // ==================================================================
    // پایان کار
    // ==================================================================

    private fun setPhase(p: Phase) {
        phase = p
        callbacks.onPhase(p.name)
    }

    @Synchronized
    private fun shutdownInternal(reason: String?) {
        if (closedNotified) return
        closedNotified = true
        running.set(false)
        Log.i(TAG, "shutdown: $reason")
        // پایان مذاکره‌دار جلسه/تانل — نهایت تلاش
        try {
            if (sessionEstablished) {
                val avps = concatBytes(listOf(
                    L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_CDN),
                    L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_SESSION_ID, ourSessionId),
                    L2tpWire.avpU16(L2tpWire.AVP_RESULT_CODE, 1)
                ))
                sendDatagram(L2tpWire.buildControl(peerTunnelId, peerSessionId, nsOut, nrIn, avps))
                nsOut = (nsOut + 1) and 0xFFFF
            }
            val stop = concatBytes(listOf(
                L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_STOP_CCN),
                L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_TUNNEL_ID, ourTunnelId),
                L2tpWire.avpU16(L2tpWire.AVP_RESULT_CODE, 1)
            ))
            sendDatagram(L2tpWire.buildControl(peerTunnelId, 0, nsOut, nrIn, stop))
        } catch (_: Throwable) { }

        try { socket?.close() } catch (_: Throwable) { }
        socket = null
        try { tunHandle?.close() } catch (_: Throwable) { }
        tunHandle = null
        phase = Phase.CLOSED
        callbacks.onClosed(reason)
    }

    private fun resolveServer(host: String): InetAddress? = try {
        val parts = host.trim().split(":")
        if (parts.size == 2 && parts[1].toIntOrNull() in 1..65535) {
            serverPort = parts[1].toInt()
            InetAddress.getByName(parts[0])
        } else {
            InetAddress.getByName(host.trim())
        }
    } catch (_: Throwable) {
        null
    }

    private fun concatBytes(list: List<ByteArray>): ByteArray {
        var total = 0
        for (b in list) total += b.size
        val out = ByteArray(total)
        var pos = 0
        for (b in list) { System.arraycopy(b, 0, out, pos, b.size); pos += b.size }
        return out
    }

    companion object {
        private const val TAG = "SecureLink-L2TP"
        const val HELLO_INTERVAL_DEFAULT_MS = 25_000L
        const val CONNECT_DEADLINE_DEFAULT_MS = 45_000L
    }
}
