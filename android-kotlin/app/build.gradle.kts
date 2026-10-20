import java.io.ByteArrayOutputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.roborazzi)
}

val ndkVersion = "27.2.12479018"
val rustDir = rootProject.layout.projectDirectory.dir("rust")
val jniLibsOut = layout.buildDirectory.dir("generated/jniLibs")
val uniffiOut = layout.buildDirectory.dir("generated/uniffi/kotlin")
// Debug APKs use the Rust `dev` profile (optimised dependencies, quick to compile);
// pass -PrustRelease=true for the fat-LTO `release` profile.
// A benchmark build is release-grade by definition, so it takes the Rust `release` profile too.
val benchmarkRequested = gradle.startParameter.taskNames.any { it.contains("benchmark", ignoreCase = true) }
val rustRelease = providers.gradleProperty("rustRelease").map(String::toBoolean).orElse(benchmarkRequested)
val rustAbis = listOf("arm64-v8a", "x86_64")
// The embedded renderer (browser/data-browser/embed.html), built by scripts/build_embed.sh
// into build output and bundled as assets/embed. -PskipEmbed=true bundles an empty
// placeholder instead (JVM unit tests and Rust work need no Node).
val embedOut = layout.buildDirectory.dir("generated/embed/assets")
val skipEmbed = providers.gradleProperty("skipEmbed").map(String::toBoolean).orElse(false)

android {
    namespace = "place.atomic.app.kotlin"
    compileSdk = 35
    ndkVersion = this@Build_gradle.ndkVersion

    defaultConfig {
        applicationId = "place.atomic.app.kotlin"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += rustAbis }
    }

    buildTypes {
        debug {
            buildConfigField("boolean", "PERF_MARKS", "true")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
            buildConfigField("boolean", "PERF_MARKS", "false")
        }
        // Release-like (minified, not debuggable, release Rust) but profileable, with the
        // seed and the [perf] marks: what perf runs measure. See README "Benchmark build".
        create("benchmark") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            isDebuggable = false
            signingConfig = signingConfigs.getByName("debug")
            buildConfigField("boolean", "PERF_MARKS", "true")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    sourceSets.getByName("main") {
        jniLibs.srcDir(jniLibsOut)
        kotlin.srcDir(uniffiOut)
        assets.srcDir(embedOut)
    }

    // The seed and the fake AI exist in debug and benchmark builds (src/seeded), as stubs in release.
    sourceSets.getByName("debug") { kotlin.srcDir("src/seeded/kotlin") }
    sourceSets.getByName("benchmark") { kotlin.srcDir("src/seeded/kotlin") }

    testOptions { unitTests { isIncludeAndroidResources = true } }

    packaging { jniLibs { useLegacyPackaging = false } }
}

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.coroutines.android)
    // UniFFI's Kotlin bindings load the Rust library through JNA.
    implementation("${libs.jna.get()}@aar")
    // Pairing: QR scanning (CameraX frames decoded by ZXing, no Google Play services needed) and drawing this device's own code.
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(platform(libs.compose.bom))
    testImplementation(libs.compose.ui.test.junit4)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(libs.roborazzi.junit.rule)
}

roborazzi {
    outputDir.set(file(System.getenv("ROBORAZZI_OUTPUT_DIR") ?: "build/outputs/roborazzi"))
}

// ── Rust: cargo-ndk, then UniFFI's Kotlin bindings from the built library ────

val androidHome: String? = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")

fun Exec.rustEnvironment() {
    val sdk = androidHome ?: error("Set ANDROID_HOME to the Android SDK (see android-kotlin/README.md)")
    environment("ANDROID_HOME", sdk)
    environment("ANDROID_NDK_HOME", "$sdk/ndk/$ndkVersion")
    // The target dir is private to this crate, never the shared `build-dir`
    // of ~/.cargo/config.toml (one lock for every repo, see AGENTS.md).
    environment("CARGO_BUILD_BUILD_DIR", rustDir.dir("target/build").asFile.absolutePath)
}

val rustInputs = fileTree(rustDir) { include("src/**", "Cargo.toml", "Cargo.lock", "uniffi.toml") }
val atomicLibInputs = fileTree(rootProject.layout.projectDirectory.dir("../lib")) { include("src/**", "Cargo.toml") }

val cargoNdk by tasks.registering(Exec::class) {
    group = "rust"
    description = "Builds libatomic_kotlin_rust.so for arm64-v8a and x86_64 with cargo-ndk."
    workingDir = rustDir.asFile
    rustEnvironment()
    inputs.files(rustInputs, atomicLibInputs)
    inputs.property("release", rustRelease)
    outputs.dir(jniLibsOut)
    doFirst {
        val args = mutableListOf("cargo", "ndk", "--platform", "26")
        rustAbis.forEach { args += listOf("-t", it) }
        args += listOf("-o", jniLibsOut.get().asFile.absolutePath, "build")
        if (rustRelease.get()) args += "--release"
        commandLine(args)
    }
    doLast {
        // cargo-ndk copies every cdylib the build produced; the iroh crates
        // bring two the app never loads.
        jniLibsOut.get().asFile.walkTopDown()
            .filter { it.isFile && it.name != "libatomic_kotlin_rust.so" }
            .forEach { it.delete() }
    }
}

val uniffiBindgen by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generates the Kotlin bindings (build/generated/uniffi) from the built library."
    dependsOn(cargoNdk)
    workingDir = rustDir.asFile
    rustEnvironment()
    inputs.files(rustInputs)
    inputs.dir(jniLibsOut)
    outputs.dir(uniffiOut)
    doFirst {
        val library = jniLibsOut.get().asFile.resolve("arm64-v8a/libatomic_kotlin_rust.so")
        commandLine(
            "cargo", "run", "--quiet", "--features", "cli", "--bin", "uniffi-bindgen", "--",
            "generate", "--library", library.absolutePath, "--language", "kotlin",
            "--config", rustDir.file("uniffi.toml").asFile.absolutePath,
            "--out-dir", uniffiOut.get().asFile.absolutePath, "--no-format",
        )
    }
}

tasks.named("preBuild") { dependsOn(uniffiBindgen) }

// ── The embedded renderer, from the repo's own vite embed config ──────────────

val buildEmbed by tasks.registering(Exec::class) {
    group = "embed"
    description = "Builds browser/data-browser's embed.html and bundles it as assets/embed."
    val browser = rootProject.layout.projectDirectory.dir("../browser")
    val script = rootProject.layout.projectDirectory.file("scripts/build_embed.sh")
    val out = embedOut.map { it.dir("embed") }
    inputs.files(fileTree(browser) {
        include("data-browser/src/**", "data-browser/*.html", "data-browser/vite*.ts", "data-browser/package.json",
            "lib/src/**", "react/src/**", "pnpm-lock.yaml")
        exclude("**/node_modules/**", "**/dist/**", "**/dist-embed/**")
    })
    inputs.file(script)
    inputs.property("skip", skipEmbed)
    outputs.dir(out)
    doFirst {
        if (skipEmbed.get()) {
            out.get().asFile.apply { deleteRecursively(); mkdirs() }
            File(out.get().asFile, "embed.html").writeText("<!doctype html><title>embed not built</title>")
            commandLine("true")
        } else {
            commandLine("bash", script.asFile.absolutePath, out.get().asFile.absolutePath)
        }
    }
}

tasks.matching { it.name.matches(Regex("merge.*Assets")) }.configureEach { dependsOn(buildEmbed) }

// Lint models read the bundled assets too (the release-like benchmark build runs lint vital).
tasks.matching { it.name.contains("lint", ignoreCase = true) }.configureEach { dependsOn(buildEmbed) }
