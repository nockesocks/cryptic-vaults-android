plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "me.nocke.cryptic.vaults"
    compileSdk = 36

    defaultConfig {
        applicationId = "me.nocke.cryptic.vaults"
        minSdk = 34
        targetSdk = 36
        versionCode = 2
        versionName = "0.2.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild { ndkBuild { path = file("src/main/cpp/Android.mk") } }
    defaultConfig { ndk { abiFilters += "arm64-v8a" } }

    testOptions {
        unitTests.all { it.systemProperty("vectors.dir", rootProject.file("test-vectors/out").path) }
    }
}

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    // YubiKey as an app lock: USB transport, CTAP2 and the FIDO PIN protocol (Yubico's SDK; no network code)
    implementation("com.yubico.yubikit:android:3.0.1")
    implementation("com.yubico.yubikit:fido:3.0.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
