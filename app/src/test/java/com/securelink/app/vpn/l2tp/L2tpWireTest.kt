package com.securelink.app.vpn.l2tp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * تست‌های سطح سیم L2TP/PPP — قفل‌کردن قالب بسته‌ها مطابق RFC 2661/1661.
 * شامل رگرسیون باگ بحرانی طول گزینه‌های LCP/IPCP (Opt.bytes).
 */
class L2tpWireTest {

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format("%02x", it) }

    private fun unhex(s: String): ByteArray =
        ByteArray(s.length / 2) { i -> ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte() }

    @Test
    fun `control packet round-trip with T L S bits`() {
        val avps = L2tpWire.avpU16(L2tpWire.AVP_MESSAGE_TYPE, L2tpWire.MSG_SCCRQ)
        val pkt = L2tpWire.buildControl(1234, 0, 5, 7, avps)
        assertEquals(0xc8, pkt[0].toInt() and 0xFF)          // T=1, L=1
        assertEquals(0x02, pkt[1].toInt() and 0xFF)          // Ver=2
        val parsed = L2tpWire.parse(pkt, pkt.size)!!
        assertTrue(parsed.isControl)
        assertEquals(1234, parsed.tunnelId)
        assertEquals(0, parsed.sessionId)
        assertEquals(5, parsed.ns)
        assertEquals(7, parsed.nr)
        val list = L2tpWire.parseAvps(pkt, parsed.payloadOffset, parsed.payloadEnd)
        assertEquals(L2tpWire.MSG_SCCRQ, L2tpWire.findAvp(list, L2tpWire.AVP_MESSAGE_TYPE)!!.u16())
    }

    @Test
    fun `data packet has 4002 header and round-trips`() {
        val payload = byteArrayOf(1, 2, 3, 4)
        val pkt = L2tpWire.buildData(777, 555, payload)
        assertEquals(0x40, pkt[0].toInt() and 0xFF)          // L=1, T=0
        assertEquals(0x02, pkt[1].toInt() and 0xFF)
        val parsed = L2tpWire.parse(pkt, pkt.size)!!
        assertEquals(false, parsed.isControl)
        assertEquals(777, parsed.tunnelId)
        assertEquals(555, parsed.sessionId)
        assertEquals(payload.toList(), pkt.copyOfRange(parsed.payloadOffset, parsed.payloadEnd).toList())
    }

    @Test
    fun `mikrotik style data packet without length field parses`() {
        // 0x0002: بدون Length — TunnelID + SessionID + payload
        val pkt = unhex("000203e9022bdeadbeef")
        val parsed = L2tpWire.parse(pkt, pkt.size)!!
        assertEquals(false, parsed.isControl)
        assertEquals(1001, parsed.tunnelId)
        assertEquals(555, parsed.sessionId)
        assertEquals(listOf<Byte>(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte()),
            pkt.copyOfRange(parsed.payloadOffset, parsed.payloadEnd).toList())
    }

    @Test
    fun `data packet with sequence fields parses`() {
        // 0x0002 + S-bit (0x0800) → 0802
        val pkt = unhex("080203e9022b0005000701020304")
        val parsed = L2tpWire.parse(pkt, pkt.size)!!
        assertEquals(false, parsed.isControl)
        assertEquals(5, parsed.ns)
        assertEquals(7, parsed.nr)
        assertEquals(listOf<Byte>(1, 2, 3, 4), pkt.copyOfRange(parsed.payloadOffset, parsed.payloadEnd).toList())
    }

    @Test
    fun `option bytes length is 2 plus value size - regression for corrupted ACK`() {
        // باگ قبلی: بایت طول = value.size می‌شد و ACK سمت سرور خراب بود
        val mru = L2tpWire.Opt(1, byteArrayOf(0x05, 0xaa.toByte()))
        val encoded = mru.bytes()
        assertEquals("01040 5aa".replace(" ", ""), hex(encoded))
        assertEquals(4, encoded[1].toInt())

        val ip = L2tpWire.Opt(3, byteArrayOf(0x0a, 0, 0, 1))
        assertEquals(6, ip.bytes()[1].toInt())

        // Reject سه گزینه Callback/PFC/ACFC باید گزینه‌های سالم با طول درست داشته باشد
        val callback = L2tpWire.Opt(0x0D, byteArrayOf(0))
        val pfc = L2tpWire.Opt(7, byteArrayOf())
        val acfc = L2tpWire.Opt(8, byteArrayOf())
        val data = callback.bytes() + pfc.bytes() + acfc.bytes()
        val parsed = L2tpWire.parseOptions(data)
        assertEquals(listOf(0x0D, 7, 8), parsed.map { it.type })
    }

    @Test
    fun `ppp control packet round-trip with address control field`() {
        val frame = L2tpWire.pppControlPacket(L2tpWire.PPP_LCP, L2tpWire.CODE_ECHO_REQUEST, 9, byteArrayOf(1, 2, 3, 4))
        assertEquals(0xFF, frame[0].toInt() and 0xFF)
        assertEquals(0x03, frame[1].toInt() and 0xFF)
        assertEquals(0xC0, frame[2].toInt() and 0xFF)
        assertEquals(0x21, frame[3].toInt() and 0xFF)
        val (protocol, packet) = L2tpWire.parsePpp(frame, 0, frame.size)!!
        assertEquals(L2tpWire.PPP_LCP, protocol)
        assertEquals(L2tpWire.CODE_ECHO_REQUEST, packet.code)
        assertEquals(9, packet.id)
        assertEquals(listOf<Byte>(1, 2, 3, 4), packet.data.toList())
    }

    @Test
    fun `ppp frame with single byte protocol falls back (PFC)`() {
        // IPv4 با پروتکل تک‌بایتی 0x21 (PFC سمت سرور) — یک بسته IP کامل ۲۰ بایتی
        val ip = ByteArray(20)
        ip[0] = 0x45
        ip[2] = 0; ip[3] = 20
        val frame = byteArrayOf(0xFF.toByte(), 0x03.toByte(), 0x21) + ip
        val (protocol, _) = L2tpWire.parsePpp(frame, 0, frame.size)!!
        assertEquals(L2tpWire.PPP_IPV4, protocol)
    }

    @Test
    fun `auth option encodes chap algorithms as 3 bytes`() {
        assertEquals("030 4c02 3".replace(" ", ""), hex(L2tpWire.optAuth(L2tpWire.AUTH_PAP)))
        assertEquals("030 5c22 381".replace(" ", ""), hex(L2tpWire.optAuth(L2tpWire.AUTH_MSCHAP2)))
        assertEquals("030 5c22 380".replace(" ", ""), hex(L2tpWire.optAuth(L2tpWire.AUTH_MSCHAP1)))
        assertEquals("030 5c22 305".replace(" ", ""), hex(L2tpWire.optAuth(L2tpWire.AUTH_CHAP_MD5)))
    }

    @Test
    fun `ip option encodes 6 bytes`() {
        val opt = L2tpWire.optIp(L2tpWire.IPCP_OPT_PRIMARY_DNS, L2tpWire.bytesToIp(byteArrayOf(1, 2, 3, 4)))
        assertEquals("810 601020304".replace(" ", ""), hex(opt))
    }

    @Test
    fun `ip conversion round-trips`() {
        val ip = L2tpWire.bytesToIp(byteArrayOf(192.toByte(), 168.toByte(), 88.toByte(), 1))
        assertEquals("192.168.88.1", L2tpWire.ipToString(ip))
    }

    @Test
    fun `parse rejects garbage and short packets`() {
        assertNull(L2tpWire.parse(byteArrayOf(1, 2, 3), 3))
        assertNull(L2tpWire.parse(ByteArray(10) { 0 }, 10))   // Ver=0
    }

    @Test
    fun `hidden avp is skipped without value decode`() {
        val avp = L2tpWire.avp(11, byteArrayOf(1, 2, 3, 4), mandatory = false)
        avp[0] = (avp[0].toInt() or 0x40).toByte()   // H=1
        val list = L2tpWire.parseAvps(avp, 0, avp.size)
        assertEquals(1, list.size)
        assertTrue(list[0].hidden)
        assertEquals(0, list[0].value.size)
    }
}
