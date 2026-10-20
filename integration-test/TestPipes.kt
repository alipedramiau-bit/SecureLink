package itest

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * لوله دوطرفه درون‌حافظه‌ای برای شبیه‌سازی رابط TUN در تست JVM.
 */
class BlockingPipe(private val capacity: Int = 64 * 1024) {
    private val queue = ArrayBlockingQueue<ByteArray>(capacity)
    @Volatile private var closed = false

    fun put(packet: ByteArray) {
        if (closed) throw IOException("pipe closed")
        queue.put(packet)
    }

    fun poll(timeoutMs: Long): ByteArray? {
        if (closed && queue.isEmpty()) throw IOException("pipe closed")
        return queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
    }

    fun close() {
        closed = true
    }
}

private class PipeInputStream(private val pipe: BlockingPipe) : InputStream() {
    override fun read(): Int = throw UnsupportedOperationException("use read(byte[])")
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        while (true) {
            val p = pipe.poll(200) ?: continue   // بستهٔ کامل برمی‌گردد نه بایت‌به‌بایت
            val n = minOf(p.size, len)
            System.arraycopy(p, 0, b, off, n)
            return n
        }
    }
}

private class PipeOutputStream(private val pipe: BlockingPipe) : OutputStream() {
    override fun write(b: Int) = throw UnsupportedOperationException("use write(byte[])")
    override fun write(b: ByteArray, off: Int, len: Int) {
        pipe.put(b.copyOfRange(off, off + len))
    }
    override fun flush() {}
}

/**
 * پیاده‌سازی TunHandle برای تست — همان رابطی که در اندروید با ParcelFileDescriptor ساخته می‌شود.
 *
 *  - outputStream: کلاینت بسته‌های «دریافتی از شبکه» را اینجا می‌نویسد (ورودی TUN)
 *  - inputStream : کلاینت بسته‌های «خروجی اپ» را از اینجا می‌خواند (خروجی TUN)
 */
internal class FakeTun : com.securelink.app.vpn.l2tp.L2tpClient.TunHandle {
    val fromNetwork = BlockingPipe()   // نوشته‌شده توسط کلاینت — تست می‌خواند
    val toNetwork = BlockingPipe()     // نوشته‌شده توسط تست — کلاینت می‌خواند

    override val outputStream: OutputStream = PipeOutputStream(fromNetwork)
    override val inputStream: InputStream = PipeInputStream(toNetwork)

    var closedByClient = false
        private set

    override fun close() {
        closedByClient = true
        fromNetwork.close()
        toNetwork.close()
    }

    /** یک بسته IP خروجی به TUN تزریق می‌کند (انگار اپ فرستاده). */
    fun injectOutbound(packet: ByteArray) = toNetwork.put(packet)

    /** بسته IP نوشته‌شده توسط کلاینت در TUN را می‌خواند (بسته‌ای که شبکه تحویل داده). */
    fun readDelivered(timeoutMs: Long): ByteArray? = fromNetwork.poll(timeoutMs)
}
