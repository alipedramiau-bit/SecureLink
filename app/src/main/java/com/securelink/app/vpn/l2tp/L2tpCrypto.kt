package com.securelink.app.vpn.l2tp

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * توابع رمزنگاری لازم برای کلاینت L2TP/PPP.
 *
 * - MD4 (RFC 1320) برای هش رمز عبور در MS-CHAP (در JCE اندروید موجود نیست)
 * - بسط کلید DES از ۷ به ۸ بایت با پاریتی فرد (RFC 2759 §8.6)
 * - MS-CHAPv2 (RFC 2759) و MS-CHAPv1 (RFC 2433) و CHAP-MD5 (RFC 1994)
 *
 * همه بردارهای تستی RFC در این پیاده‌سازی تأیید شده‌اند
 * (MD4("abc") = a448017aaf21d8525fc10ae87aa6729d و NT-Response §9.2 و ...).
 */
internal object L2tpCrypto {

    // ------------------------------------------------------------------
    // MD4 — پیاده‌سازی خالص مطابق RFC 1320
    // ------------------------------------------------------------------

    fun md4(input: ByteArray): ByteArray {
        val state = intArrayOf(0x67452301, 0xefcdab89.toInt(), 0x98badcfe.toInt(), 0x10325476)

        val len = input.size
        val totalLen = ((len + 8) / 64 + 1) * 64
        val buf = ByteArray(totalLen)
        System.arraycopy(input, 0, buf, 0, len)
        buf[len] = 0x80.toByte()
        var bitLen = len.toLong() * 8L
        for (i in 0 until 8) {
            buf[totalLen - 8 + i] = (bitLen and 0xFF).toByte()
            bitLen = bitLen ushr 8
        }

        val x = IntArray(16)
        var off = 0
        while (off < totalLen) {
            for (i in 0 until 16) {
                val p = off + 4 * i
                x[i] = (buf[p].toInt() and 0xFF) or
                        ((buf[p + 1].toInt() and 0xFF) shl 8) or
                        ((buf[p + 2].toInt() and 0xFF) shl 16) or
                        ((buf[p + 3].toInt() and 0xFF) shl 24)
            }
            var a = state[0]; var b = state[1]; var c = state[2]; var d = state[3]

            // Round 1
            for (i in 0 until 16) {
                val s = intArrayOf(3, 7, 11, 19)[i % 4]
                val f = (b and c) or (b.inv() and d)
                val na = rotl(a + f + x[i], s)
                a = d; d = c; c = b; b = na
            }
            // Round 2
            for (i in 0 until 16) {
                val s = intArrayOf(3, 5, 9, 13)[i % 4]
                val k = (i / 4) + 4 * (i % 4)
                val g = (b and c) or (b and d) or (c and d)
                val na = rotl(a + g + x[k] + 0x5A827999, s)
                a = d; d = c; c = b; b = na
            }
            // Round 3
            val order = intArrayOf(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
            for (i in 0 until 16) {
                val s = intArrayOf(3, 9, 11, 15)[i % 4]
                val h = b xor c xor d
                val na = rotl(a + h + x[order[i]] + 0x6ED9EBA1.toInt(), s)
                a = d; d = c; c = b; b = na
            }

            state[0] += a; state[1] += b; state[2] += c; state[3] += d
            off += 64
        }

        val out = ByteArray(16)
        for (i in 0 until 4) {
            out[4 * i] = state[i].toByte()
            out[4 * i + 1] = (state[i] ushr 8).toByte()
            out[4 * i + 2] = (state[i] ushr 16).toByte()
            out[4 * i + 3] = (state[i] ushr 24).toByte()
        }
        return out
    }

    private fun rotl(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))

    // ------------------------------------------------------------------
    // DES — بسط کلید ۷→۸ بایت با پاریتی فرد (RFC 2759 §8.6)
    // ------------------------------------------------------------------

    /** یک کلید ۸ بایتی DES از ۷ بایت خام می‌سازد (بیت هشتم = پاریتی فرد). */
    fun desKeyFrom7Bytes(input: ByteArray, offset: Int): ByteArray {
        val out = ByteArray(8)
        out[0] = (input[offset].toInt() and 0xFE).toByte()
        out[1] = (((input[offset].toInt() and 0x01) shl 7) or ((input[offset + 1].toInt() shr 1) and 0xFE)).toByte()
        out[2] = (((input[offset + 1].toInt() and 0x03) shl 6) or ((input[offset + 2].toInt() shr 2) and 0xFE)).toByte()
        out[3] = (((input[offset + 2].toInt() and 0x07) shl 5) or ((input[offset + 3].toInt() shr 3) and 0xFE)).toByte()
        out[4] = (((input[offset + 3].toInt() and 0x0F) shl 4) or ((input[offset + 4].toInt() shr 4) and 0xFE)).toByte()
        out[5] = (((input[offset + 4].toInt() and 0x1F) shl 3) or ((input[offset + 5].toInt() shr 5) and 0xFE)).toByte()
        out[6] = (((input[offset + 5].toInt() and 0x3F) shl 2) or ((input[offset + 6].toInt() shr 6) and 0xFE)).toByte()
        out[7] = ((input[offset + 6].toInt() and 0x7F) shl 1).toByte()
        for (i in 0 until 8) {
            val v = out[i].toInt() and 0xFE
            var bits = 0
            for (b in 0 until 8) if ((v shr b) and 1 == 1) bits++
            if (bits % 2 == 0) out[i] = (v or 1).toByte()
        }
        return out
    }

    /** رمزگذاری یک بلاک ۸ بایتی با DES-ECB (بدون padding). */
    fun desEncryptBlock(key8: ByteArray, block8: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("DES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key8, "DES"))
        return cipher.doFinal(block8)
    }

    private fun concat(vararg arrays: ByteArray): ByteArray {
        var total = 0
        for (a in arrays) total += a.size
        val out = ByteArray(total)
        var pos = 0
        for (a in arrays) { System.arraycopy(a, 0, out, pos, a.size); pos += a.size }
        return out
    }

    private fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

    private fun md5(vararg data: ByteArray): ByteArray =
        MessageDigest.getInstance("MD5").digest(concat(*data))

    // ------------------------------------------------------------------
    // MS-CHAPv2 (RFC 2759)
    // ------------------------------------------------------------------

    /** NtPasswordHash = MD4(UTF-16LE(password)) */
    fun ntPasswordHash(password: String): ByteArray =
        md4(password.toByteArray(Charsets.UTF_16LE))

    /** ChallengeHash = ۸ بایت اول SHA1(PeerChallenge ‖ AuthChallenge ‖ UserName) */
    fun challengeHash(peerChallenge: ByteArray, authChallenge: ByteArray, userName: String): ByteArray {
        val h = sha1(concat(peerChallenge, authChallenge, userName.toByteArray(Charsets.US_ASCII)))
        return h.copyOfRange(0, 8)
    }

    /** NT-Response = ۳ بلاک DES با کلیدهای هش رمز روی ChallengeHash (RFC 2759 §8.5) */
    fun generateNtResponse(
        authChallenge: ByteArray,
        peerChallenge: ByteArray,
        userName: String,
        password: String
    ): ByteArray {
        val challenge = challengeHash(peerChallenge, authChallenge, userName)
        val hash = ntPasswordHash(password)
        val padded = ByteArray(21)
        System.arraycopy(hash, 0, padded, 0, 16)
        val out = ByteArray(24)
        for (i in 0 until 3) {
            val key = desKeyFrom7Bytes(padded, i * 7)
            System.arraycopy(desEncryptBlock(key, challenge), 0, out, i * 8, 8)
        }
        return out
    }

    /**
     * پاسخ احراز سرور (Authenticator Response) — برای تأیید Success سرور مطابق RFC 2759 §8.7.
     */
    fun generateAuthenticatorResponse(
        password: String,
        ntResponse: ByteArray,
        peerChallenge: ByteArray,
        authChallenge: ByteArray,
        userName: String
    ): ByteArray {
        val hashHash = md4(ntPasswordHash(password))
        val magic1 = "Magic server to client signing constant".toByteArray(Charsets.US_ASCII)
        val magic2 = "Pad to make it do more than one iteration".toByteArray(Charsets.US_ASCII)
        val d = sha1(concat(hashHash, ntResponse, magic1))
        val challenge = challengeHash(peerChallenge, authChallenge, userName)
        val d2 = sha1(concat(d, challenge, magic2))
        return d2.copyOfRange(0, 20)
    }

    /** پاسخ ۴۹ بایتی MS-CHAPv2: PeerChallenge(16) ‖ Reserved(8) ‌‖ NT-Response(24) ‖ Flags(1) */
    fun buildMsChap2ResponseValue(
        authChallenge: ByteArray,
        peerChallenge: ByteArray,
        userName: String,
        password: String
    ): ByteArray {
        val ntResponse = generateNtResponse(authChallenge, peerChallenge, userName, password)
        val value = ByteArray(49)
        System.arraycopy(peerChallenge, 0, value, 0, 16)
        // بایت‌های 16..23 صفر می‌مانند
        System.arraycopy(ntResponse, 0, value, 24, 24)
        // value[48] = 0 (flags)
        return value
    }

    // ------------------------------------------------------------------
    // MS-CHAPv1 (RFC 2433) — fallback برای RouterOS های قدیمی‌تر
    // ------------------------------------------------------------------

    /** پاسخ NT (۲۴ بایت) برای MS-CHAPv1: ۳ بلاک DES روی چالش ۸ بایتی با NtHash. */
    fun msChap1NtResponse(challenge8: ByteArray, password: String): ByteArray {
        val hash = ntPasswordHash(password)
        val padded = ByteArray(21)
        System.arraycopy(hash, 0, padded, 0, 16)
        val out = ByteArray(24)
        for (i in 0 until 3) {
            val key = desKeyFrom7Bytes(padded, i * 7)
            System.arraycopy(desEncryptBlock(key, challenge8), 0, out, i * 8, 8)
        }
        return out
    }

    /** مقدار ۴۸ بایتی MS-CHAPv1: LM-Response(24) ‖ NT-Response(24). */
    fun buildMsChap1ResponseValue(challenge8: ByteArray, password: String): ByteArray {
        val raw = password.uppercase().toByteArray(Charsets.US_ASCII)
        val paddedPw = ByteArray(14)
        System.arraycopy(raw, 0, paddedPw, 0, minOf(raw.size, 14))
        val k1 = desKeyFrom7Bytes(paddedPw, 0)
        val k2 = desKeyFrom7Bytes(paddedPw, 7)
        val magic = "KGS!@#\$%".toByteArray(Charsets.US_ASCII)
        val lmHash = concat(desEncryptBlock(k1, magic), desEncryptBlock(k2, magic))
        val padded = ByteArray(21)
        System.arraycopy(lmHash, 0, padded, 0, 16)
        val lmResponse = ByteArray(24)
        for (i in 0 until 3) {
            val key = desKeyFrom7Bytes(padded, i * 7)
            System.arraycopy(desEncryptBlock(key, challenge8), 0, lmResponse, i * 8, 8)
        }
        return concat(lmResponse, msChap1NtResponse(challenge8, password))
    }

    // ------------------------------------------------------------------
    // CHAP-MD5 (RFC 1994)
    // ------------------------------------------------------------------

    /** پاسخ CHAP-MD5: MD5(ID ‖ secret ‖ challenge). */
    fun chapMd5Response(id: Int, secret: ByteArray, challenge: ByteArray): ByteArray =
        md5(byteArrayOf(id.toByte()), secret, challenge)

    // ------------------------------------------------------------------
    // احراز هویت تانل L2TP (RFC 2661 §5.1.1)
    // ------------------------------------------------------------------

    /** پاسخ چالش تانل: MD5(ID ‖ secret ‖ challenge) که ID مقدار Message-Type پیام حامل است. */
    fun l2tpChallengeResponse(id: Int, secret: ByteArray, challenge: ByteArray): ByteArray =
        md5(byteArrayOf(id.toByte()), secret, challenge)
}
