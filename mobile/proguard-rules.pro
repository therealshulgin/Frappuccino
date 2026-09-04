# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in <android-sdk>/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# S8d: AGP 8 R8 is stricter about malformed META-INF/services files. The
# bundled kxml2 2.3.0 jar ships a single-line
# `META-INF/services/org.xmlpull.v1.XmlPullParserFactory` containing
# `org.kxml2.io.KXmlParser,org.kxml2.io.KXmlSerializer` (comma instead of
# newline). R8 parses the comma-joined string as a single FQN that doesn't
# resolve → "Missing class" error. A targeted `-dontwarn <fqn>,<fqn>` doesn't
# match because R8 splits the argument on commas. `-ignorewarnings` silences
# that bucket without affecting real missing-class detection elsewhere.
-dontwarn org.kxml2.**
-ignorewarnings

# S8d: JNA 5.14 calls `Collections.synchronizedMap` at static init. D8
# rewrites the call to `j$.util.DesugarCollections.synchronizedMap`, but R8
# strips methods of DesugarCollections it doesn't see referenced in user code
# — the JNA reference is inside a renamed jar and gets missed. Force-keep
# every static in the desugar shim so the rewrite target survives R8.
-keep class j$.util.DesugarCollections {
    public static <methods>;
}
-keep class j$.util.** {
    public static <methods>;
}

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}


# tella
-keep class rs.readahead.washington.mobile.data.entity.** { *; }

# okhttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-dontwarn org.conscrypt.**
# A resource is loaded with a relative path so the package of this class must be preserved.
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# old okhttp?
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.ParametersAreNonnullByDefault

# retrofit2 (http://square.github.io/retrofit/)
-dontnote retrofit2.Platform
-dontnote retrofit2.Platform$IOS$MainThreadExecutor
-dontwarn retrofit2.Platform$Java8
-keepattributes Signature
-keepattributes Exceptions
-dontwarn javax.annotation.**

# Gson
-keepattributes *Annotation*

# Gson specific classes
-keep class sun.misc.Unsafe { *; }
#-keep class com.google.gson.stream.** { *; }
-keep class com.google.gson.** { *; }

# Preserve the special static methods that are required in all enumeration classes.
-keepclassmembers class * extends java.lang.Enum {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}


# Retain generated class which implement Unbinder.
#-keep public class * implements butterknife.Unbinder { public <init>(**, android.view.View); }


# Prevent obfuscation of types which use ButterKnife annotations since the simple name
# is used to reflectively look up the generated ViewBinding.
#-keep class butterknife.*
#-keepclasseswithmembernames class * { @butterknife.* <methods>; }
#-keepclasseswithmembernames class * { @butterknife.* <fields>; }


# simplexml
# Keep public classes and methods.
-dontwarn com.bea.xml.stream.**
-dontwarn org.simpleframework.xml.stream.**
-keep class org.simpleframework.xml.**{ *; }
-keepclassmembers,allowobfuscation class * {
    @org.simpleframework.xml.* <fields>;
    @org.simpleframework.xml.* <init>(...);
}


# collect
#-dontwarn com.google.**
#-dontwarn au.com.bytecode.**
-dontwarn org.joda.time.**
#-dontwarn org.osmdroid.**
-dontwarn org.xmlpull.v1.**
-keep public class org.xmlpull.**
-keep class org.javarosa.**
#-keep class android.support.v7.widget.** { *; }


# todo: check which one
-dontwarn org.xmlpull.v1.**
-dontnote org.xmlpull.v1.**
-keep class org.xmlpull.** { *; }


# crashalytics
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
# Note: ancienne règle '-keep public class * extends java.lang.Exception' supprimée
# pour permettre l'obfuscation des Exceptions internes (ex: PinProtectedStore$WrongPinException).
# Les stacktraces obfusquées se déchiffrent via mobile/build/outputs/mapping/release/mapping.txt.
-keep class com.crashlytics.** { *; }
-dontwarn com.crashlytics.**


#android additional
-keep public class android.support.v7.widget.** { *; }
-keep public class android.support.v7.internal.widget.** { *; }
-keep public class android.support.v7.internal.view.menu.** { *; }

-keep public class android.support.v4.widget.** { *; }
-keep public class android.support.v4.internal.widget.** { *; }
-keep public class android.support.v4.internal.view.menu.** { *; }

-keep public class * extends android.support.v4.view.ActionProvider {
    public <init>(android.content.Context);
}


# sqlcypher
#-libraryjars libs/commons-codec.jar
#-libraryjars libs/guava-r09.jar
#-libraryjars libs/sqlcipher.jar

-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-dontskipnonpubliclibraryclassmembers
-dontpreverify
-verbose
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*,!code/allocation/variable

-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application

-dontwarn javax.annotation.**

-dontwarn android.app.**
-dontwarn android.support.**
-dontwarn android.view.**
-dontwarn android.widget.**

-dontwarn com.google.common.primitives.**

-dontwarn **CompatHoneycomb
-dontwarn **CompatHoneycombMR2
-dontwarn **CompatCreatorHoneycombMR2

-keepclasseswithmembernames class * {
    native <methods>;
}

-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}

-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

-keepclassmembers class * extends android.app.Activity {
   public void *(android.view.View);
}

-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator *;
}

-keepclassmembers class **.R$* {
    public static <fields>;
}

-keep class net.zetetic.database.** { *; }
-keep class net.zetetic.database.sqlcipher.** { *; }

-dontwarn net.sqlcipher.**

# odk collect
-dontwarn com.google.**
-dontwarn au.com.bytecode.**
-dontwarn org.joda.time.**
-dontwarn org.osmdroid.**
-dontwarn org.xmlpull.v1.**

-keep class org.javarosa.**
-keep class android.support.v7.widget.** { *; }

# slf4j
-keep class org.slf4j.** { *; }
-dontwarn org.slf4j.**

# Android-Image-Cropper
-keep class androidx.appcompat.widget.** { *; }

-keep class androidx.** { *; }

# --- crypto-rs UniFFI bindings + JNA --------------------------------------
# JNA uses reflection heavily. Strip it and nothing works.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
# UniFFI generated bindings must be preserved (cross-FFI callbacks).
-keep class uniffi.** { *; }
# Instrumented tests (androidTestRust/) referenced by class name via
# android.testInstrumentationRunnerArguments.class — R8 would otherwise strip.
-keep class org.stream.crypto.rust.** { *; }
-keep class org.stream.crypto.parity.** { *; }
# Kotlin stdlib extensions used at test-time (writeText, readBytes, sb.last(),
# isNotEmpty(), etc.). R8 aggressively strips these static helpers if it can't
# see them referenced from non-test code. Broad keep for stdlib so the parity
# dumper and RustSmokeTest don't hit NoSuchMethodError on every extension.
-keep class kotlin.io.** { *; }
-keep class kotlin.text.** { *; }
-keep class kotlin.collections.** { *; }
-keep class kotlin.jvm.internal.Intrinsics { *; }
# Keep all stream-crypto API reachable from the parity dumper — R8 would
# otherwise strip methods like PinProtectedStore.unseal that aren't referenced
# from production code paths.
-keep class org.stream.crypto.** { *; }
-dontwarn androidx.**