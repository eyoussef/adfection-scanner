import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

/**
 * Release signing.
 *
 * Credentials are read from `keystore.properties`, which is gitignored and lives outside the repo —
 * a store signing key in a public repository would let anyone ship an update as this app. When the
 * file is absent (CI, a fresh clone, a contributor) the release build is simply left unsigned rather
 * than failing, so `assembleDebug` and the test suite keep working everywhere.
 *
 * Losing this keystore means the published app can never be updated again; it must be backed up
 * separately from this machine.
 */
val keystoreProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) {
        file.inputStream().use { load(it) }
    }
}

android {
    namespace = "dev.adfection.scanner"
    compileSdk = 35

    signingConfigs {
        if (keystoreProperties.isNotEmpty()) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    defaultConfig {
        applicationId = "dev.adfection.scanner"
        minSdk = 29
        targetSdk = 35
        versionCode = 11
        versionName = "0.9.0"
    }

    buildTypes {
        release {
            // R8 is intentionally disabled: the app ships unobfuscated so defenders can audit it.
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.findByName("release")
            // Leave the default signing schemes alone: AGP emits v2 + v3, which covers every API
            // level this app supports and keeps key-rotation proof. Setting enableV3Signing here
            // explicitly turned v2 OFF, which apksigner confirmed — a good example of a "safer"
            // flag doing the opposite.
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }

    packaging {
        resources.excludes += setOf("META-INF/*.kotlin_module")
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.0")
    implementation("androidx.recyclerview:recyclerview:1.3.1")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("com.google.android.material:material:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    // Official WireGuard for Android tunnel library (Apache-2.0, WireGuard LLC).
    // Bundles libwg-go.so for arm64-v8a/armeabi-v7a/x86/x86_64.
    implementation("com.wireguard.android:tunnel:1.0.20230706")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")

    // The android.jar handed to unit tests stubs org.json, so JSONObject returns nulls and any
    // test touching it silently passes on nothing. Wire the real implementation in for tests:
    // org.json is part of the Android platform at runtime, so this only affects the JVM test run.
    testImplementation("org.json:json:20240303")
}
