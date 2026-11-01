# JNA looks its classes and fields up by name, and the UniFFI bindings pass
# their structures and callbacks through it: keep both from R8.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class me.somalabs.onepass.core.** { *; }
-dontwarn java.awt.**
