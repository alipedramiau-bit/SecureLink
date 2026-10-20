package android.util

/**
 * شیم «android.util.Log» فقط برای اجرای مستقل تست یکپارچگی روی JVM.
 * این فایل هرگز در بیلد اندروید وارد نمی‌شود (فقط توسط integration-test/run.sh کامپایل می‌شود).
 */
object Log {
    fun d(tag: String?, msg: String?): Int { println("[D] $tag: $msg"); return 0 }
    fun i(tag: String?, msg: String?): Int { println("[I] $tag: $msg"); return 0 }
    fun w(tag: String?, msg: String?): Int { println("[W] $tag: $msg"); return 0 }
    fun e(tag: String?, msg: String?): Int { println("[E] $tag: $msg"); return 0 }
    fun d(tag: String?, msg: String?, tr: Throwable?): Int { println("[D] $tag: $msg (${tr?.message})"); return 0 }
    fun i(tag: String?, msg: String?, tr: Throwable?): Int { println("[I] $tag: $msg (${tr?.message})"); return 0 }
    fun w(tag: String?, msg: String?, tr: Throwable?): Int { println("[W] $tag: $msg (${tr?.message})"); return 0 }
    fun e(tag: String?, msg: String?, tr: Throwable?): Int { println("[E] $tag: $msg (${tr?.message})"); return 0 }
}
