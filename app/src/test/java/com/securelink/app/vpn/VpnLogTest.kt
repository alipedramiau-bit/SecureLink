package com.securelink.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * تست واحد VpnLog — کاملاً JVM (بدون وابستگی اندروید).
 */
class VpnLogTest {

    @Test
    fun `log appends lines with tag`() {
        VpnLog.clear()
        VpnLog.log("L2TP", "line-1")
        VpnLog.log("SVC", "line-2")
        val snap = VpnLog.snapshot()
        assertTrue(snap.contains("L2TP: line-1"))
        assertTrue(snap.contains("SVC: line-2"))
        assertEquals(2, VpnLog.lineCount())
    }

    @Test
    fun `log replaces newlines to keep single-line format`() {
        VpnLog.clear()
        VpnLog.log("L2TP", "a\nb")
        assertEquals(1, VpnLog.lineCount())
        assertTrue(VpnLog.snapshot().contains("a b"))
    }

    @Test
    fun `ring buffer caps at MAX_LINES`() {
        VpnLog.clear()
        for (i in 1..(VpnLog.MAX_LINES + 50)) VpnLog.log("T", "n$i")
        assertEquals(VpnLog.MAX_LINES, VpnLog.lineCount())
        val lines = VpnLog.snapshot().lineSequence().toList()
        // ۵۰ خط قدیمی‌ترین حذف شده‌اند: نخستین خط باقی‌مانده n51 است
        assertTrue(lines.first().endsWith("n51"))
        assertTrue(lines.last().endsWith("n${VpnLog.MAX_LINES + 50}"))
    }

    @Test
    fun `l2tpError records reason and blank becomes unknown`() {
        VpnLog.clear()
        assertNull(VpnLog.lastL2tpError)
        VpnLog.l2tpError("سرور جلسه را بست")
        assertEquals("سرور جلسه را بست", VpnLog.lastL2tpError)
        assertTrue(VpnLog.lastL2tpErrorAt > 0)
        assertTrue(VpnLog.snapshot().contains("قطع شد: سرور جلسه را بست"))

        VpnLog.l2tpError("  ")
        assertEquals("دلیل نامشخص", VpnLog.lastL2tpError)
    }

    @Test
    fun `clear empties buffer and error state`() {
        VpnLog.log("T", "x")
        VpnLog.l2tpError("y")
        VpnLog.clear()
        assertEquals(0, VpnLog.lineCount())
        assertNull(VpnLog.lastL2tpError)
        assertEquals(0L, VpnLog.lastL2tpErrorAt)
    }

    @Test
    fun `version advances on writes`() {
        VpnLog.clear()
        val v0 = VpnLog.version
        VpnLog.log("T", "x")
        assertTrue(VpnLog.version > v0)
        VpnLog.clear()
        assertTrue(VpnLog.version > v0 + 1)
        assertNotNull(VpnLog.snapshot()) // snapshot همیشه غیرتهی است
    }
}
