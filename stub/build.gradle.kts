plugins {
    id("com.android.application")
    id("org.lsposed.lsparanoid")
}

lsparanoid {
    includeDependencies = true
    global = true
}

android {
    namespace = "com.topjohnwu.magisk"

    val config = gradle.sharedServices.registrations.getByName("config").service.get() as ConfigService
    val canary = !config.version.contains(".")

    val url = if (canary) null
    else "https://cdn.jsdelivr.net/gh/topjohnwu/magisk-files@${config.version}/app-release.apk"

    defaultConfig {
        applicationId = "com.topjohnwu.magisk"
        versionCode = 1
        versionName = "1.0"
        buildConfigField("int", "STUB_VERSION", config.stubVersion)
        buildConfigField("String", "APK_URL", url?.let { "\"$it\"" } ?: "null" )
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            proguardFiles("proguard-rules.pro")
        }
    }
}

setupStub()

dependencies {
    implementation(project(":app:shared"))
}
