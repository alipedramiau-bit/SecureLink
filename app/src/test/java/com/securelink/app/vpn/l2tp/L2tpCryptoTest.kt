package com.securelink.app.vpn.l2tp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * تست‌های رمزنگاری L2TP/PPP با بردارهای استاندارد (RFC 1320 / 2433 / 2759 / 1994).
 */
class L2tpCryptoTest {

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format("%02x", it) }

    @Test
    fun `md4 matches RFC 1320 test vectors`() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", hex(L2tpCrypto.md4(ByteArray(0))))
        // MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        assertEquals("a448017aaf21d8525fc10ae87aa6729d",
            hex(L2tpCrypto.md4("abc".toByteArray(Charsets.US_ASCII))))
        // MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
        assertEquals("d79e1c308aa5bbcdeea8ed63df412da9",
            hex(L2tpCrypto.md4("abcdefghijklmnopqrstuvwxyz".toByteArray(Charsets.US_ASCII))))
    }

    @Test
    fun `nt password hash is md4 of utf16le`() {
        val expected = L2tpCrypto.md4("clientPass".toByteArray(Charsets.UTF_16LE))
        assertEquals(expected.toList(), L2tpCrypto.ntPasswordHash("clientPass").toList())
        assertEquals(16, L2tpCrypto.ntPasswordHash("x").size)
    }

    @Test
    fun `des key expansion produces odd parity bytes`() {
        val raw = byteArrayOf(0x01, 0x23, 0x45, 0x67, 0x69.toByte(), 0xAB.toByte(), 0xCD.toByte())
        val key = L2tpCrypto.desKeyFrom7Bytes(raw, 0)
        assertEquals(8, key.size)
        for (b in key) {
            var bits = 0
            for (i in 0 until 8) if ((b.toInt() shr i) and 1 == 1) bits++
            assertTrue("بایت بدون پاریتی فرد: %02x".format(b), bits % 2 == 1)
        }
    }

    @Test
    fun `chap md5 response equals md5 of id secret challenge`() {
        val secret = "AdHjKl".toByteArray()
        val challenge = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val expected = MessageDigest.getInstance("MD5")
            .digest(byteArrayOf(0x2A) + secret + challenge)
        assertEquals(hex(expected), hex(L2tpCrypto.chapMd5Response(0x2A, secret, challenge)))
    }

    @Test
    fun `challenge hash is first 8 bytes of sha1`() {
        val peer = ByteArray(16) { it.toByte() }
        val auth = ByteArray(16) { (it + 1).toByte() }
        val expected = MessageDigest.getInstance("SHA-1")
            .digest(peer + auth + "User".toByteArray(Charsets.US_ASCII)).copyOfRange(0, 8)
        assertEquals(hex(expected), hex(L2tpCrypto.challengeHash(peer, auth, "User")))
    }

    @Test
    fun `mschap2 response value is 49 bytes with zero reserved and flags`() {
        val authChallenge = ByteArray(16) { (it * 3).toByte() }
        val peerChallenge = ByteArray(16) { (it * 7 + 1).toByte() }
        val value = L2tpCrypto.buildMsChap2ResponseValue(authChallenge, peerChallenge, "User", "Pass")
        assertEquals(49, value.size)
        // بایت‌های 16..23 محفوظ و صفر (RFC 2759 §8.5)
        for (i in 16..23) assertEquals(0.toByte(), value[i])
        // flags صفر
        assertEquals(0.toByte(), value[48])
        // peerChallenge در ابتدای مقدار
        assertEquals(peerChallenge.toList(), value.copyOfRange(0, 16).toList())
        // NT-Response در بایت‌های 24..47
        val nt = L2tpCrypto.generateNtResponse(authChallenge, peerChallenge, "User", "Pass")
        assertEquals(nt.toList(), value.copyOfRange(24, 48).toList())
    }

    @Test
    fun `mschap1 response value is 49 bytes with zero LM and flags 1`() {
        val challenge = ByteArray(8) { (it + 3).toByte() }
        val value = L2tpCrypto.buildMsChap1ResponseValue(challenge, "Pass")
        assertEquals(49, value.size)
        // LM-Response صفر طبق توصیه RFC 2433
        for (i in 0..23) assertEquals(0.toByte(), value[i])
        assertEquals(0x01.toByte(), value[48])
        val nt = L2tpCrypto.msChap1NtResponse(challenge, "Pass")
        assertEquals(nt.toList(), value.copyOfRange(24, 48).toList())
    }

    @Test
    fun `nt response is deterministic 24 bytes`() {
        val authChallenge = ByteArray(16) { (it + 5).toByte() }
        val peerChallenge = ByteArray(16) { (it + 9).toByte() }
        val a = L2tpCrypto.generateNtResponse(authChallenge, peerChallenge, "u", "p")
        val b = L2tpCrypto.generateNtResponse(authChallenge, peerChallenge, "u", "p")
        assertEquals(24, a.size)
        assertEquals(a.toList(), b.toList())
    }

    @Test
    fun `authenticator response is 20 bytes`() {
        val authChallenge = ByteArray(16) { (it + 5).toByte() }
        val peerChallenge = ByteArray(16) { (it + 9).toByte() }
        val nt = L2tpCrypto.generateNtResponse(authChallenge, peerChallenge, "u", "p")
        val resp = L2tpCrypto.generateAuthenticatorResponse("p", nt, peerChallenge, authChallenge, "u")
        assertEquals(20, resp.size)
    }

    @Test
    fun `l2tp tunnel challenge response equals md5 of type secret challenge`() {
        val secret = "topsecret".toByteArray(Charsets.US_ASCII)
        val challenge = ByteArray(16) { (it * 11).toByte() }
        val expected = MessageDigest.getInstance("MD5")
            .digest(byteArrayOf(3) + secret + challenge)   // 3 = MSG_SCCCN
        assertEquals(hex(expected), hex(L2tpCrypto.l2tpChallengeResponse(3, secret, challenge)))
    }
}
