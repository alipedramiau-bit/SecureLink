# قوانین ProGuard پروژه SecureLink
# چون minifyEnabled=false است فعال نیست؛ در صورت فعال‌سازی این قوانین را نگه دارید.

-keep class com.wireguard.config.** { *; }
-keep class com.wireguard.crypto.** { *; }
-keep class com.wireguard.android.backend.** { *; }

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.securelink.app.data.** { *; }
-dontwarn com.google.errorprone.annotations.**
