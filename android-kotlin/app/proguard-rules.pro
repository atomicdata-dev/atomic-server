# UniFFI's generated Kotlin talks to the Rust library through JNA.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
-keep class place.atomic.app.kotlin.core.** { *; }
-dontwarn java.awt.**
