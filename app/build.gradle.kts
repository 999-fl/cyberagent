plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.cyberagent.mobile"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.cyberagent.mobile"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-alpha"
    }
    buildFeatures { compose = true }
}
dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.compose.ui:ui:1.7.6")
    implementation("androidx.compose.ui:ui-tooling-preview:1.7.6")
    implementation("androidx.compose.material3:material3:1.3.1")
    implementation("androidx.compose.material:material:1.7.6")
    implementation("androidx.compose.foundation:foundation:1.7.6")
    implementation("androidx.compose.runtime:runtime:1.7.6")
    implementation("androidx.compose.ui:ui-graphics:1.7.6")
    implementation("androidx.compose.ui:ui-text:1.7.6")
    implementation("androidx.compose.ui:ui-tooling:1.7.6")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.json:json:20240303")
}
