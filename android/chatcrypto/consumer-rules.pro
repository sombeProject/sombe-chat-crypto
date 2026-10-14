# JNA finds the bindings and its own classes by reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class org.sombe.chatcrypto.** { *; }
-dontwarn java.awt.**
