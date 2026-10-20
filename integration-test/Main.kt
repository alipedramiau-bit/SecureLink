package itest

/**
 * اجراکننده همه سناریوهای تست یکپارچگی L2TP.
 * خروجی: کد خروج ۰ اگر همه سناریوها سبز باشند، وگرنه ۱.
 */
fun main() {
    val scenarios = listOf<Pair<String, () -> String>>(
        "S1_full_handshake_mschap2_data_keepalive" to { Scenarios.s1FullHandshakeDataKeepalive() },
        "S2_chap_md5" to { Scenarios.s2ChapMd5() },
        "S3_pap" to { Scenarios.s3Pap() },
        "S4_zlb_regression_rfc2661_5_8" to { Scenarios.s4ZlbRegression() },
        "S5_tunnel_secret" to { Scenarios.s5TunnelSecret() },
        "S6_wrong_password_691" to { Scenarios.s6WrongPassword() },
        "S7_mtu_1400_roundtrip" to { Scenarios.s7MtuSizePacket() },
        "S8_sequencing_required" to { Scenarios.s8SequencingRequired() }
    )

    println("=== SecureLink L2TP Integration Test ===")
    var failed = 0
    for ((name, fn) in scenarios) {
        val t0 = System.currentTimeMillis()
        try {
            val detail = fn()
            println("[PASS] $name (${System.currentTimeMillis() - t0} ms) — $detail")
        } catch (t: Throwable) {
            failed++
            println("[FAIL] $name (${System.currentTimeMillis() - t0} ms) — ${t.message}")
            t.printStackTrace()
        }
    }
    println("=== ${scenarios.size - failed}/${scenarios.size} scenarios passed ===")
    kotlin.system.exitProcess(failed)
}
