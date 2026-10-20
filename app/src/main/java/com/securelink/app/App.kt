package com.securelink.app

import android.app.Application
import com.securelink.app.data.ProfileStore

/**
 * کلاس اپلیکیشن؛ پروفایل‌های ذخیره‌شده را در شروع بارگذاری می‌کند.
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()
        ProfileStore.load(this)
    }
}
