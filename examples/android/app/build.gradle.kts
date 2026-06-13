plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.kseal.quickstart"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.kseal.quickstart"
        minSdk = 24
        @Suppress("DEPRECATION")
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // Wire the sample without editing code. The trust endpoint defaults to
        // the Android emulator's host loopback (10.0.2.2) so `make docker-up`
        // on the host machine is reachable from the emulator.
        buildConfigField("String", "KSEAL_TENANT", "\"${project.findProperty("ksealTenant") ?: "acme"}\"")
        buildConfigField("String", "KSEAL_APP", "\"${project.findProperty("ksealApp") ?: "com.acme.app"}\"")
        buildConfigField("String", "KSEAL_API_KEY", "\"${project.findProperty("ksealApiKey") ?: ""}\"")
        buildConfigField("String", "KSEAL_ENDPOINT", "\"${project.findProperty("ksealEndpoint") ?: "http://10.0.2.2:8080"}\"")
        // Google Play Integrity cloud project number; 0 selects the dev token
        // provider (see AttestationTokenProvider.kt).
        buildConfigField("long", "KSEAL_GCP_PROJECT", "${project.findProperty("ksealGcpProject") ?: 0}L")
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // The kseal Android SDK, built from source via the composite build in
    // settings.gradle.kts (no Maven publish needed).
    implementation("io.kseal:kseal-android:0.1.0")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // OkHttp drives the TrustService HTTP/JSON calls the host owns. org.json
    // ships in the Android framework (android.jar), so it is NOT declared as a
    // dependency here — adding the Maven artifact would cause a D8 duplicate
    // class error for org.json.*.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Real Play Integrity provider (used when ksealGcpProject is set).
    implementation("com.google.android.play:integrity:1.4.0")
}
