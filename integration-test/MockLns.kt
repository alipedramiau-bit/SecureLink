package itest

import com.securelink.app.vpn.l2tp.L2tpCrypto
import com.securelink.app.vpn.l2tp.L2tpWire
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.Random
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * سرور L2TP/PPP شبیه‌سازی‌شده (رفتار MikroTik RouterOS / xl2tpd) برای تست یکپارچگی کلاینت.
 *
 * نکته کلیدی: توالی کانال کنترل دقیقاً مطابق RFC 2661 §5.8 پیاده شده —
 * یعنی ZLB حاوی Nsِ «فعلی و مصرف‌نشده» است و اسلاتی مصرف نمی‌کند.
 * اگر کلاینت (مثل کد قدیمی) Nr را با Nsِ ZLB جلو ببرد، سناریوهای S4 شکست می‌خورند.
 */
class MockLns(
    val auth: Auth = Auth.MSCHAP2,
    val useSecret: String? = null,
    val dns1: String = "1.1.1.1",
    val dns2: String = "8.8.8.8",
    val clientIp: String = "10.0.0.50"
) {
    enum class Auth { MSCHAP2, CHAP_MD5, PAP }

    val events = object : ConcurrentLinkedQueue<String>() {
        override fun add(e: String): Boolean = if (size < 5000) super.add(e) else false
    }
    private val random = Random()

    private var socket: DatagramSocket? = null
    @Volatile private var running = false
    private var thread: Thread? = null

    // شناسه‌های سمت کلاینت (از SCCRQ/ICRQ خوانده می‌شود)
    var clientTid = 0; private set
    var clientSid = 0; private set
    private var clientCtr = 0          // next expected Ns از کلاینت

    // توالی سمت سرور: شمارنده پیام‌های «واقعی» (ZLB مصرف نمی‌کند — RFC 2661 §5.8)
    var serverNs = 0
        private set

    // وضعیت LCP/IPCP سمت سرور
    private var serverLcpReqId = 99
    private var serverLcpOpts = listOf<ByteArray>()
    private var serverLcpAcked = false
    private var serverIpcpReqId = 199
    private var serverIpcpSent = false
    private var serverIpcpAcked = false
    private var chapChallenge = ByteArray(0)
    private var chapChallengeId = 5

    val port: Int get() = socket?.localPort ?: -1

    // ------------------------------------------------------------------

    fun start() {
        val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        sock.reuseAddress = true
        socket = sock
        running = true
        thread = Thread({
            val buf = ByteArray(4096)
            while (running) {
                try {
                    sock.soTimeout = 500
                    val dp = DatagramPacket(buf, buf.size)
                    sock.receive(dp)
                    lastClient = dp.socketAddress
                    handle(buf.copyOf(dp.length))
                } catch (_: SocketTimeoutException) {
                } catch (t: Throwable) {
                    if (running) events.add("MOCK_ERROR(${t.message})")
                }
            }
        }, "MockLns")
        thread?.start()
    }

    fun close() {
        running = false
        try { socket?.close() } catch (_: Throwable) {}
    }

    /** کپی لحظه‌ای رویدادها برای assertions. */
    fun snapshot(): List<String> = events.toList()

    fun countEvents(prefix: String): Int = events.count { it.startsWith(prefix) }

    private fun send(bytes: ByteArray) {
        try {
            socket?.send(DatagramPacket(bytes, bytes.size, lastClient))
        } catch (t: Throwable) {
            events.add("MOCK_SEND_ERROR(${t.message})")
        }
    }

    private var lastClient: java.net.SocketAddress = java.net.InetSocketAddress("127.0.0.1", 9)

    // ------------------------------------------------------------------
    // دریافت
    // ------------------------------------------------------------------

    private fun handle(pkt: ByteArray) {
        val parsed = L2tpWire.parse(pkt, pkt.size)
        if (parsed == null) {
            events.add("MOCK_UNPARSEABLE(hex=${pkt.take(24).joinToString("") { String.format("%02x", it) }})")
            return
        }
        if (parsed.isControl) handleControl(pkt, parsed) else handleData(pkt, parsed)
    }

    private fun handleControl(pkt: ByteArray, p: L2tpWire.ParsedPacket) {
        val avps = L2tpWire.parseAvps(pkt, p.payloadOffset, p.payloadEnd)
        val type = L2tpWire.findAvp(avps, L2tpWire.AVP_MESSAGE_TYPE)?.u16()
        if (type == null) {
            // ZLB — Ns مصرف نمی‌کند؛ فقط flush با Nr (RFC 2661 §5.8)
            events.add("CLIENT_ZLB(Ns=${p.ns},Nr=${p.nr})")
            return
        }
        when {
            p.ns == clientCtr -> {
                clientCtr = (clientCtr + 1) and 0xFFFF
                processControl(type, avps, p)
            }
            isBehind(p.ns, clientCtr) -> events.add("CLIENT_RETRANSMIT(type=$type,ns=${p.ns})")
            else -> events.add("CLIENT_SEQ_ANOMALY(type=$type,ns=${p.ns},expected=$clientCtr)")
        }
    }

    private fun isBehind(ns: Int, base: Int): Boolean =
        ((base - ns) and 0xFFFF) in 1..0x7FFF

    private fun processControl(type: Int, avps: List<L2tpWire.Avp>, p: L2tpWire.ParsedPacket) {
        when (type) {
            L2tpWire.MSG_SCCRQ -> {
                clientTid = L2tpWire.findAvp(avps, L2tpWire.AVP_ASSIGNED_TUNNEL_ID)?.u16() ?: 0
                events.add("CLIENT_SCCRQ(tid=$clientTid)")
                val list = ArrayList<ByteArray>()
                list.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_SCCRP))
                list.add(L2tpWire.avpU16(L2tpWire.AVP_PROTOCOL_VERSION, 0x0100))
                list.add(L2tpWire.avpText(L2tpWire.AVP_HOST_NAME, "MockLNS"))
                list.add(L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_TUNNEL_ID, 777))
                list.add(L2tpWire.avpU16(L2tpWire.AVP_RECEIVE_WINDOW_SIZE, 4))
                if (useSecret != null) {
                    list.add(L2tpWire.avp(L2tpWire.AVP_CHALLENGE, randomChallenge(), true))
                }
                sendControl(L2tpWire.MSG_SCCRP, 0, concat(list))
            }
            L2tpWire.MSG_SCCCN -> {
                if (useSecret != null) {
                    val resp = L2tpWire.findAvp(avps, L2tpWire.AVP_CHALLENGE_RESPONSE)?.value
                    val ok = resp != null && resp.contentEquals(L2tpCrypto.l2tpChallengeResponse(
                        L2tpWire.MSG_SCCCN, useSecret!!.toByteArray(Charsets.US_ASCII), lastChallenge))
                    events.add("CLIENT_SCCCN(secretOk=$ok)")
                } else {
                    events.add("CLIENT_SCCCN")
                }
            }
            L2tpWire.MSG_ICRQ -> {
                clientSid = L2tpWire.findAvp(avps, L2tpWire.AVP_ASSIGNED_SESSION_ID)?.u16() ?: 0
                events.add("CLIENT_ICRQ(sid=$clientSid)")
                val list = ArrayList<ByteArray>()
                list.add(L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_ICRP))
                list.add(L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_SESSION_ID, 555))
                sendControl(L2tpWire.MSG_ICRP, clientSid, concat(list))
            }
            L2tpWire.MSG_ICCN -> {
                events.add("CLIENT_ICCN")
                // ACK با ZLB — طبق RFC، Ns مصرف نمی‌کند
                sendZlb()
                // شروع PPP: سرور ConfReq خودش را می‌فرستد (با گزینه‌هایی که باید Reject شوند)
                sendServerLcpConfReq()
            }
            L2tpWire.MSG_HELLO -> {
                events.add("CLIENT_HELLO")
                sendZlb()
            }
            L2tpWire.MSG_CDN -> events.add("CLIENT_CDN")
            L2tpWire.MSG_STOP_CCN -> events.add("CLIENT_STOP_CCN")
            else -> events.add("CLIENT_CTRL_OTHER(type=$type)")
        }
    }

    private fun handleData(pkt: ByteArray, p: L2tpWire.ParsedPacket) {
        val parsedPpp = L2tpWire.parsePpp(pkt, p.payloadOffset, p.payloadEnd) ?: run {
            events.add("MOCK_BAD_PPP"); return
        }
        val (protocol, pp) = parsedPpp
        when (protocol) {
            L2tpWire.PPP_LCP -> handleLcp(pp)
            L2tpWire.PPP_CHAP -> handleChap(pp)
            L2tpWire.PPP_PAP -> handlePap(pp)
            L2tpWire.PPP_IPCP -> handleIpcp(pp)
            L2tpWire.PPP_IPV4 -> {
                val start = ipv4Start(pkt, p.payloadOffset, p.payloadEnd)
                if (start >= 0) {
                    val ip = pkt.copyOfRange(start, p.payloadEnd)
                    events.add("DATA_FROM_CLIENT(len=${ip.size})")
                    lastClientIpPacket = ip
                    // اکو: همان بسته IP به کلاینت برگردد
                    val frame = L2tpWire.pppFrame(L2tpWire.PPP_IPV4, ip)
                    send(L2tpWire.buildData(clientTid, clientSid, frame))
                }
            }
            else -> events.add("MOCK_PPP_OTHER(${Integer.toHexString(protocol)})")
        }
    }

    private var lastClientIpPacket: ByteArray? = null

    private fun ipv4Start(buf: ByteArray, offset: Int, end: Int): Int {
        var i = offset
        if (i + 2 <= end && buf[i] == 0xFF.toByte() && buf[i + 1] == 0x03.toByte()) i += 2
        if (i + 2 > end) return -1
        val proto = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
        i += 2
        return if (proto == L2tpWire.PPP_IPV4) i else -1
    }

    // ------------------------------------------------------------------
    // سمت سرور PPP
    // ------------------------------------------------------------------

    private fun handleLcp(p: L2tpWire.PppPacket) {
        when (p.code) {
            L2tpWire.CODE_CONFIGURE_REQUEST -> {
                val opts = L2tpWire.parseOptions(p.data)
                events.add("CLIENT_LCP_CONFREQ(${opts.joinToString(",") { optName(it.type) }})")
                sendPpp(L2tpWire.PPP_LCP, L2tpWire.CODE_CONFIGURE_ACK, p.id, p.data)
            }
            L2tpWire.CODE_CONFIGURE_ACK -> {
                if (p.id == serverLcpReqId) {
                    serverLcpAcked = true
                    events.add("CLIENT_LCP_ACK_OURS")
                    if (auth == Auth.PAP) {
                        // PAP را کلاینت خودش شروع می‌کند — چیزی نمی‌فرستیم
                    } else {
                        sendChapChallenge()
                    }
                }
            }
            L2tpWire.CODE_CONFIGURE_REJECT -> {
                val rejected = L2tpWire.parseOptions(p.data).map { it.type }
                events.add("CLIENT_LCP_REJECT(${rejected.joinToString(",") { optName(it) }})")
                serverLcpOpts = serverLcpOpts.filter { opt -> opt[0].toInt() and 0xFF !in rejected }
                sendServerLcpConfReq()
            }
            L2tpWire.CODE_ECHO_REPLY -> events.add("CLIENT_ECHO_REPLY(id=${p.id})")
            else -> events.add("CLIENT_LCP_OTHER(code=${p.code})")
        }
    }

    private fun sendServerLcpConfReq() {
        if (serverLcpOpts.isEmpty()) {
            serverLcpOpts = buildList {
                add(L2tpWire.optU16(L2tpWire.LCP_OPT_MRU, 1460))
                add(L2tpWire.optU32(L2tpWire.LCP_OPT_MAGIC, 0xA5A5A5A5))
                when (auth) {
                    Auth.MSCHAP2 -> add(L2tpWire.optAuth(L2tpWire.AUTH_MSCHAP2))
                    Auth.CHAP_MD5 -> add(L2tpWire.optAuth(L2tpWire.AUTH_CHAP_MD5))
                    Auth.PAP -> add(L2tpWire.optAuth(L2tpWire.AUTH_PAP))
                }
                add(byteArrayOf(0x0D, 3, 0))          // Callback — باید Reject شود
                add(byteArrayOf(0x07, 2))             // PFC  — باید Reject شود
                add(byteArrayOf(0x08, 2))             // ACFC — باید Reject شود
            }
        }
        serverLcpReqId = (serverLcpReqId + 1) and 0xFF
        sendPpp(L2tpWire.PPP_LCP, L2tpWire.CODE_CONFIGURE_REQUEST, serverLcpReqId, concat(serverLcpOpts))
    }

    private fun sendChapChallenge() {
        chapChallenge = ByteArray(16).also { random.nextBytes(it) }
        chapChallengeId = (chapChallengeId + 1) and 0xFF
        val body = ByteArray(1 + chapChallenge.size)
        body[0] = chapChallenge.size.toByte()
        System.arraycopy(chapChallenge, 0, body, 1, chapChallenge.size)
        sendPppAuth(L2tpWire.PPP_CHAP, 1, chapChallengeId, body)
        events.add("SERVER_CHAP_CHALLENGE(id=$chapChallengeId)")
    }

    private fun handleChap(p: L2tpWire.PppPacket) {
        when (p.code) {
            2 -> {   // Response
                if (p.data.isEmpty()) { events.add("CLIENT_CHAP_RESPONSE(empty)"); return }
                val valueSize = p.data[0].toInt() and 0xFF
                val value = p.data.copyOfRange(1, 1 + valueSize)
                val name = String(p.data.copyOfRange(1 + valueSize, p.data.size), Charsets.UTF_8)
                when (auth) {
                    Auth.MSCHAP2 -> {
                        events.add("CLIENT_CHAP_RESPONSE(v2,vs=$valueSize,user=$name)")
                        if (valueSize != 49) { sendChapFailure("E=691"); return }
                        val peerChallenge = value.copyOfRange(0, 16)
                        val ntResponse = value.copyOfRange(24, 48)
                        val reserved = value.copyOfRange(16, 24)
                        if (reserved.any { it != 0.toByte() }) { events.add("CLIENT_CHAP_RESERVED_DIRTY") }
                        val expected = L2tpCrypto.generateNtResponse(chapChallenge, peerChallenge, name, password)
                        if (!ntResponse.contentEquals(expected)) {
                            events.add("CLIENT_CHAP_NT_MISMATCH"); sendChapFailure("E=691"); return
                        }
                        val authResp = L2tpCrypto.generateAuthenticatorResponse(
                            password, ntResponse, peerChallenge, chapChallenge, name)
                        val hex = authResp.joinToString("") { String.format("%02X", it) }
                        sendPppAuth(L2tpWire.PPP_CHAP, 3, p.id, "S=$hex M=OK".toByteArray(Charsets.UTF_8))
                        events.add("SERVER_CHAP_SUCCESS")
                        sendServerIpcpConfReq()
                    }
                    Auth.CHAP_MD5 -> {
                        events.add("CLIENT_CHAP_RESPONSE(md5,vs=$valueSize,user=$name)")
                        val expected = MessageDigest.getInstance("MD5").digest(
                            byteArrayOf(p.id.toByte()) + password.toByteArray(Charsets.UTF_8) + chapChallenge)
                        if (valueSize != 16 || !value.contentEquals(expected)) {
                            events.add("CLIENT_CHAP_MD5_MISMATCH"); sendChapFailure("E=691"); return
                        }
                        sendPppAuth(L2tpWire.PPP_CHAP, 3, p.id, ByteArray(0))
                        events.add("SERVER_CHAP_SUCCESS")
                        sendServerIpcpConfReq()
                    }
                    else -> events.add("CLIENT_CHAP_UNEXPECTED")
                }
            }
            else -> events.add("CLIENT_CHAP_OTHER(code=${p.code})")
        }
    }

    private fun sendChapFailure(msg: String) {
        sendPppAuth(L2tpWire.PPP_CHAP, 4, chapChallengeId, msg.toByteArray(Charsets.UTF_8))
    }

    private fun handlePap(p: L2tpWire.PppPacket) {
        when (p.code) {
            1 -> {
                if (p.data.size < 4) { events.add("CLIENT_PAP_REQUEST(bad)"); return }
                val uLen = p.data[0].toInt() and 0xFF
                val user = String(p.data.copyOfRange(1, 1 + uLen), Charsets.UTF_8)
                val pLen = p.data[1 + uLen].toInt() and 0xFF
                val pass = String(p.data.copyOfRange(2 + uLen, 2 + uLen + pLen), Charsets.UTF_8)
                events.add("CLIENT_PAP_REQUEST(user=$user,passOk=${pass == password})")
                sendPppAuth(L2tpWire.PPP_PAP, 2, p.id, ByteArray(0))
                events.add("SERVER_PAP_ACK")
                sendServerIpcpConfReq()
            }
            else -> events.add("CLIENT_PAP_OTHER(code=${p.code})")
        }
    }

    private fun handleIpcp(p: L2tpWire.PppPacket) {
        when (p.code) {
            L2tpWire.CODE_CONFIGURE_REQUEST -> {
                val opts = L2tpWire.parseOptions(p.data)
                val ipOpt = opts.firstOrNull { it.type == L2tpWire.IPCP_OPT_IP_ADDRESS }
                val ip = if (ipOpt != null && ipOpt.value.size == 4) L2tpWire.bytesToIp(ipOpt.value) else 0
                events.add("CLIENT_IPCP_REQ(ip=${L2tpWire.ipToString(ip)})")
                if (ip == 0) {
                    // Nak با آدرس واقعی + DNS
                    val nak = concat(listOf(
                        L2tpWire.optIp(L2tpWire.IPCP_OPT_IP_ADDRESS, ipToInt(clientIp)),
                        L2tpWire.optIp(L2tpWire.IPCP_OPT_PRIMARY_DNS, ipToInt(dns1)),
                        L2tpWire.optIp(L2tpWire.IPCP_OPT_SECONDARY_DNS, ipToInt(dns2))
                    ))
                    sendPpp(L2tpWire.PPP_IPCP, L2tpWire.CODE_CONFIGURE_NAK, p.id, nak)
                } else {
                    sendPpp(L2tpWire.PPP_IPCP, L2tpWire.CODE_CONFIGURE_ACK, p.id, p.data)
                    events.add("SERVER_IPCP_ACK_CLIENT")
                    sendServerIpcpConfReq()
                }
            }
            L2tpWire.CODE_CONFIGURE_ACK -> {
                if (p.id == serverIpcpReqId) {
                    serverIpcpAcked = true
                    events.add("CLIENT_IPCP_ACK_OURS")
                }
            }
            L2tpWire.CODE_CONFIGURE_REJECT -> {
                val rejected = L2tpWire.parseOptions(p.data).map { it.type }
                events.add("CLIENT_IPCP_REJECT(${rejected.joinToString(",") { optName(it) }})")
            }
            else -> events.add("CLIENT_IPCP_OTHER(code=${p.code})")
        }
    }

    private fun sendServerIpcpConfReq() {
        if (serverIpcpSent) return
        serverIpcpSent = true
        val opts = listOf(
            L2tpWire.optIp(L2tpWire.IPCP_OPT_IP_ADDRESS, ipToInt("10.0.0.1")),
            L2tpWire.optIp(L2tpWire.IPCP_OPT_PRIMARY_DNS, ipToInt(dns1)),
            L2tpWire.optIp(L2tpWire.IPCP_OPT_SECONDARY_DNS, ipToInt(dns2))
        )
        sendPpp(L2tpWire.PPP_IPCP, L2tpWire.CODE_CONFIGURE_REQUEST, serverIpcpReqId, concat(opts))
        events.add("SERVER_IPCP_CONFREQ")
    }

    // ------------------------------------------------------------------
    // محرک‌های سمت تست
    // ------------------------------------------------------------------

    /** LCP Echo-Request از سمت سرور (keepalive PPP همانند MikroTik). */
    fun sendLcpEchoRequest(id: Int) {
        sendPpp(L2tpWire.PPP_LCP, L2tpWire.CODE_ECHO_REQUEST, id, byteArrayOf(0x11, 0x22, 0x33, 0x44))
        events.add("SERVER_ECHO_REQUEST(id=$id)")
    }

    /** Hello سمت سرور — پیام واقعی، Ns مصرف می‌کند. */
    fun sendServerHello() {
        val avps = L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_HELLO)
        sendControl(L2tpWire.MSG_HELLO, 0, avps)
        events.add("SERVER_HELLO(ns=${serverNs - 1})")
    }

    /**
     * سناریوی رگرسیون ZLB: اول ZLB با Nsِ مصرف‌نشده، سپس CDN با همان Ns.
     * کلاینتِ درست باید CDN را پردازش و جلسه را ببندد (کد قدیمی آن را «تکراری» می‌پنداشت).
     */
    fun sendZlbThenCdn() {
        sendZlb()
        val result = byteArrayOf(0, 1, 0, 0)   // result=1, error=0
        val avps = concat(listOf(
            L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_CDN),
            L2tpWire.avpU16(L2tpWire.AVP_ASSIGNED_SESSION_ID, clientSid),
            L2tpWire.avp(L2tpWire.AVP_RESULT_CODE, result, true)
        ))
        sendControl(L2tpWire.MSG_CDN, clientSid, avps)
        events.add("SERVER_CDN(ns=${serverNs - 1})")
    }

    // ------------------------------------------------------------------
    // ارسال
    // ------------------------------------------------------------------

    private fun sendControl(type: Int, sessionId: Int, avpBytes: ByteArray) {
        val pkt = L2tpWire.buildControl(clientTid, sessionId, serverNs, clientCtr, avpBytes)
        serverNs = (serverNs + 1) and 0xFFFF   // پیام واقعی — Ns مصرف می‌شود
        send(pkt)
    }

    private fun sendZlb() {
        // RFC 2661 §5.8: ZLB با Nsِ فعلیِ مصرف‌نشده ارسال می‌شود و اسلاتی مصرف نمی‌کند
        send(L2tpWire.buildControl(clientTid, 0, serverNs, clientCtr, ByteArray(0)))
    }

    private fun sendPpp(protocol: Int, code: Int, id: Int, data: ByteArray) =
        send(L2tpWire.buildData(clientTid, clientSid,
            L2tpWire.pppControlPacket(protocol, code, id, data)))

    private fun sendPppAuth(protocol: Int, code: Int, id: Int, data: ByteArray) =
        send(L2tpWire.buildData(clientTid, clientSid,
            L2tpWire.pppControlPacket(protocol, code, id, data)))

    // ------------------------------------------------------------------

    var password: String = "testpass"
    private var lastChallenge = ByteArray(0)
    private fun randomChallenge(): ByteArray =
        ByteArray(16).also { random.nextBytes(it) }.also { lastChallenge = it }

    private fun optName(type: Int) = when (type) {
        1 -> "MRU"; 3 -> "AUTH"; 5 -> "MAGIC"; 7 -> "PFC"; 8 -> "ACFC"; 0x0D -> "CALLBACK"
        L2tpWire.IPCP_OPT_IP_ADDRESS -> "IP"
        L2tpWire.IPCP_OPT_PRIMARY_DNS -> "DNS1"
        L2tpWire.IPCP_OPT_SECONDARY_DNS -> "DNS2"
        else -> "OPT_$type"
    }

    private fun ipToInt(ip: String): Int {
        val parts = ip.split(".")
        var v = 0
        for (p in parts) v = (v shl 8) or (p.toInt() and 0xFF)
        return v
    }

    private fun concat(list: List<ByteArray>): ByteArray {
        var total = 0
        for (b in list) total += b.size
        val out = ByteArray(total)
        var pos = 0
        for (b in list) { System.arraycopy(b, 0, out, pos, b.size); pos += b.size }
        return out
    }
}
