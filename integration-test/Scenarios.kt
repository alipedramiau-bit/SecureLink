package itest

import com.securelink.app.vpn.l2tp.L2tpClient
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicReference

/**
 * سناریوهای تست یکپارچگی L2TP — اجرای کلاینت واقعی (L2tpClient) مقابل MockLns
 * (رفتار MikroTik/xl2tpd) روی UDP لوکال‌هاست، با TUN شبیه‌سازی‌شده.
 */
internal object Scenarios {

    internal class Ctx(
        val client: L2tpClient,
        val tun: FakeTun,
        val lns: MockLns,
        val tunConfig: AtomicReference<L2tpClient.TunConfig?>,
        val closedWith: AtomicReference<String?>,
        val phases: ConcurrentLinkedQueue<String>
    )

    // ------------------------------------------------------------------

    private fun startClient(
        lns: MockLns,
        helloMs: Long,
        user: String = "testuser",
        pass: String = "testpass",
        secret: String = ""
    ): Ctx {
        val tun = FakeTun()
        val tunConfig = AtomicReference<L2tpClient.TunConfig?>(null)
        val closedWith = AtomicReference<String?>(null)
        val phases = ConcurrentLinkedQueue<String>()
        val client = L2tpClient(
            serverAddress = "127.0.0.1:${lns.port}",
            username = user,
            password = pass,
            tunnelSecret = secret,
            protector = { true },
            tunProvider = { config -> tunConfig.set(config); tun },
            callbacks = object : L2tpClient.Callbacks {
                override fun onPhase(phase: String) { phases.add(phase) }
                override fun onClosed(error: String?) { closedWith.set(error) }
            },
            helloIntervalMs = helloMs
        )
        client.start()
        return Ctx(client, tun, lns, tunConfig, closedWith, phases)
    }

    /** بسته IP معتبر با طول دلخواه (UDP شبیه‌سازی‌شده). */
    fun makeIpPacket(len: Int = 40): ByteArray {
        val pkt = ByteArray(len)
        pkt[0] = 0x45
        pkt[1] = 0
        pkt[2] = (len ushr 8).toByte(); pkt[3] = len.toByte()
        pkt[4] = 0x12; pkt[5] = 0x34
        pkt[6] = 0x40; pkt[7] = 0
        pkt[8] = 64
        pkt[9] = 17   // UDP
        // src 10.0.0.50
        pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 50
        // dst 8.8.8.8
        pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8
        for (i in 20 until len) pkt[i] = ((i * 7) and 0xFF).toByte()
        return pkt
    }

    private fun awaitTunUp(ctx: Ctx, ip: String = "10.0.0.50") {
        awaitCondition(5_000, { ctx.tunConfig.get() != null }, { "TUN ساخته نشد. فازها: ${ctx.phases}" })
        val cfg = ctx.tunConfig.get()!!
        check(cfg.address == ip) { "IP نادرست: ${cfg.address}" }
        check(cfg.dns1 == "1.1.1.1") { "DNS1 نادرست: ${cfg.dns1}" }
        check(cfg.dns2 == "8.8.8.8") { "DNS2 نادرست: ${cfg.dns2}" }
        check(cfg.mtu == 1400) { "MTU نادرست: ${cfg.mtu}" }
    }

    private fun dataRoundTrip(ctx: Ctx, len: Int) {
        val pkt = makeIpPacket(len)
        ctx.tun.injectOutbound(pkt)
        awaitEvent(ctx.lns, "DATA_FROM_CLIENT(len=$len)", 5_000)
        val delivered = ctx.tun.readDelivered(3_000)
        check(delivered != null && delivered.contentEquals(pkt)) {
            "بسته اکو (${len}B) به TUN نرسید یا ناهمسان است"
        }
    }

    // ------------------------------------------------------------------
    // S1 — اتصال کامل MS-CHAPv2 + داده + keepalive دوطرفه + خاموشی تمیز
    // ------------------------------------------------------------------

    fun s1FullHandshakeDataKeepalive(): String {
        val lns = MockLns(auth = MockLns.Auth.MSCHAP2)
        lns.start()
        try {
            val ctx = startClient(lns, helloMs = 300)

            awaitEvent(lns, "CLIENT_SCCRQ", 5_000)
            awaitEvent(lns, "CLIENT_SCCCN", 5_000)
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_LCP_REJECT(CALLBACK,PFC,ACFC)", 5_000)
            awaitEvent(lns, "CLIENT_LCP_ACK_OURS", 5_000)
            awaitEvent(lns, "CLIENT_CHAP_RESPONSE(v2,vs=49,user=testuser)", 5_000)
            awaitEvent(lns, "SERVER_CHAP_SUCCESS", 5_000)
            awaitEvent(lns, "CLIENT_IPCP_REQ(ip=10.0.0.50)", 5_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)

            // رفت‌وبرگشت داده: اپ → TUN → L2TP → LNS → اکو → L2TP → TUN → اپ
            dataRoundTrip(ctx, 40)

            // keepalive PPP: Echo-Request سرور → Echo-Reply کلاینت
            lns.sendLcpEchoRequest(11)
            awaitEvent(lns, "CLIENT_ECHO_REPLY(id=11)", 5_000)

            // keepalive تانل: Hello سرور باید پردازش و با ZLBِ با Nrِ درست تأیید شود
            lns.sendServerHello()
            awaitEventCondition(lns, 5_000, { it.startsWith("CLIENT_ZLB") && it.contains("Nr=${lns.serverNs}") })

            // Hello های کلاینت — هیچ بازارسال/ناهنجاری توالی نباید رخ دهد
            awaitEventCount(lns, "CLIENT_HELLO", 2, 5_000)
            Thread.sleep(700)
            check(lns.countEvents("CLIENT_RETRANSMIT") == 0) {
                "بازارسال کنترلی رخ داد — ACK گم شده است: ${lns.snapshot().filter { it.contains("RETRANSMIT") }}"
            }
            check(lns.countEvents("CLIENT_SEQ_ANOMALY") == 0) { "ناهنجاری توالی: ${lns.snapshot().take(50)}" }
            check(lns.countEvents("MOCK_ERROR") == 0 && lns.countEvents("MOCK_SEND_ERROR") == 0) { "خطای MockLns" }

            // خاموشی تمیز — CDN و StopCCN به سرور
            ctx.client.shutdown("test-done")
            awaitEvent(lns, "CLIENT_CDN", 5_000)
            awaitEvent(lns, "CLIENT_STOP_CCN", 5_000)
            awaitCondition(5_000, { ctx.closedWith.get() == "test-done" }, { "onClosed فراخوانی نشد" })
            return "handshake + MSCHAPv2 + data + echo + hello + clean-shutdown"
        } finally {
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S2 — احراز هویت CHAP-MD5 (سرور C223/05 می‌خواهد)
    // ------------------------------------------------------------------

    fun s2ChapMd5(): String {
        val lns = MockLns(auth = MockLns.Auth.CHAP_MD5)
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000)
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_LCP_ACK_OURS", 5_000)
            awaitEvent(lns, "CLIENT_CHAP_RESPONSE(md5,vs=16,user=testuser)", 5_000)
            awaitEvent(lns, "SERVER_CHAP_SUCCESS", 5_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)
            return "CHAP-MD5 negotiation"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S3 — احراز هویت PAP
    // ------------------------------------------------------------------

    fun s3Pap(): String {
        val lns = MockLns(auth = MockLns.Auth.PAP)
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000)
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_LCP_ACK_OURS", 5_000)
            awaitEvent(lns, "CLIENT_PAP_REQUEST(user=testuser,passOk=true)", 5_000)
            awaitEvent(lns, "SERVER_PAP_ACK", 5_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)
            return "PAP negotiation"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S4 — رگرسیون ZLB (باگ قطع‌شدن): پیام واقعیِ بعد از ZLB باید پردازش شود
    // ------------------------------------------------------------------

    fun s4ZlbRegression(): String {
        val lns = MockLns(auth = MockLns.Auth.MSCHAP2)
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000)   // ساکت — بدون Hello کلاینت
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)

            // سرور: ZLB با Nsِ مصرف‌نشده (۲) و بلافاصله CDN با همان Ns (رفتار xl2tpd/MikroTik)
            val before = lns.snapshot().size
            lns.sendZlbThenCdn()

            // الف) ZLB کلاینت پس از ZLB سرور باید Nr == 2 داشته باشد (نه ۳!)
            awaitCondition(5_000, {
                lns.snapshot().drop(before).any { it.startsWith("CLIENT_ZLB") && it.contains("Nr=2") }
            }, { "کلاینت Nr را با Nsِ ZLB جلو برد — رگرسیون RFC 2661 §5.8! رویدادها: ${lns.snapshot()}" })

            // ب) CDN باید پردازش شود: کلاینت StopCCN بفرستد و به‌طور تمیز ببندد
            awaitEvent(lns, "CLIENT_STOP_CCN", 5_000)
            awaitCondition(5_000, { ctx.closedWith.get() != null && !ctx.client.isRunning() },
                { "پس از CDN، کلاینت باید بسته می‌شد؛ رسیده: ${ctx.closedWith.get()}" })
            check(lns.countEvents("CLIENT_SEQ_ANOMALY") == 0) { "ناهنجاری توالی: ${lns.snapshot().take(50)}" }
            return "ZLB Nr semantics + CDN-after-ZLB teardown"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S5 — رمز تانل (Tunnel Secret / Challenge)
    // ------------------------------------------------------------------

    fun s5TunnelSecret(): String {
        val lns = MockLns(auth = MockLns.Auth.MSCHAP2, useSecret = "s3cr3t")
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000, secret = "s3cr3t")
            awaitEvent(lns, "CLIENT_SCCCN(secretOk=true)", 5_000)
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)
            return "tunnel secret challenge/response"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S6 — رمز اشتباه: شکست تمیز با خطای 691
    // ------------------------------------------------------------------

    fun s6WrongPassword(): String {
        val lns = MockLns(auth = MockLns.Auth.MSCHAP2)
        lns.password = "wrongpass"   // سرور انتظار رمز دیگری دارد
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000, pass = "testpass")
            awaitEvent(lns, "SERVER_CHAP_CHALLENGE", 10_000)
            awaitCondition(10_000, { ctx.closedWith.get()?.contains("نام کاربری") == true },
                { "بسته‌شدن با خطای احراز انتظار می‌رفت؛ رسیده: ${ctx.closedWith.get()}" })
            check(!ctx.client.isRunning()) { "کلاینت هنوز در حال اجراست" }
            return "auth failure path (E=691)"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ------------------------------------------------------------------
    // S7 — داده بزرگ تا MTU (۱۴۰۰ بایت)
    // ------------------------------------------------------------------

    fun s7MtuSizePacket(): String {
        val lns = MockLns(auth = MockLns.Auth.MSCHAP2)
        lns.start()
        var ctx: Ctx? = null
        try {
            ctx = startClient(lns, helloMs = 25_000)
            awaitEvent(lns, "CLIENT_ICCN", 10_000)
            awaitEvent(lns, "CLIENT_IPCP_ACK_OURS", 5_000)
            awaitTunUp(ctx)
            dataRoundTrip(ctx, 1400)
            return "MTU-size (1400B) data round-trip"
        } finally {
            ctx?.client?.shutdown("scenario-end")
            lns.close()
        }
    }

    // ==================================================================
    // ابزارهای انتظار/بررسی
    // ==================================================================

    fun awaitEvent(lns: MockLns, exact: String, timeoutMs: Long) {
        awaitCondition(timeoutMs, { lns.snapshot().any { it.startsWith(exact) } },
            { "رویداد «$exact» دریافت نشد. رویدادها: ${lns.snapshot().take(50)}" })
    }

    fun awaitEventCount(lns: MockLns, prefix: String, count: Int, timeoutMs: Long) {
        awaitCondition(timeoutMs, { lns.snapshot().count { it.startsWith(prefix) } >= count },
            { "کمتر از $count رویداد «$prefix» — رویدادها: ${lns.snapshot().take(50)}" })
    }

    fun awaitEventCondition(lns: MockLns, timeoutMs: Long, predicate: (String) -> Boolean) {
        awaitCondition(timeoutMs, { lns.snapshot().any(predicate) },
            { "رویداد موردنظر یافت نشد. رویدادها: ${lns.snapshot().take(50)}" })
    }

    fun awaitCondition(timeoutMs: Long, predicate: () -> Boolean, message: () -> String = { "شرط برقرار نشد" }) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            Thread.sleep(50)
        }
        throw AssertionError(message())
    }
}
