import com.android.build.api.artifact.ArtifactTransformationRequest
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.dsl.ApkSigningConfig
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.gradle.BaseExtension
import com.android.build.gradle.internal.dsl.BaseAppModuleExtension
import com.android.builder.internal.packaging.IncrementalPackager
import com.android.ide.common.signing.CertificateInfo
import com.android.ide.common.signing.KeystoreHelper
import com.android.tools.build.apkzlib.sign.SigningExtension
import com.android.tools.build.apkzlib.sign.SigningOptions
import com.android.tools.build.apkzlib.zfile.ZFiles
import com.android.tools.build.apkzlib.zip.ZFileOptions
import org.apache.tools.ant.filters.FixCrLfFilter
import org.gradle.api.Action
import org.gradle.api.DefaultTask
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.plugins.ExtensionAware
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Delete
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.StopExecutionException
import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.TaskAction
import org.gradle.kotlin.dsl.filter
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.getValue
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.provideDelegate
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.registering
import org.gradle.process.ExecOperations
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmOptions
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.jar.JarFile
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.inject.Inject

private fun Project.androidBase(configure: Action<BaseExtension>) =
    extensions.configure(BaseExtension::class.java, configure)

private fun Project.android(configure: Action<BaseAppModuleExtension>) =
    extensions.configure(BaseAppModuleExtension::class.java, configure)

private fun BaseExtension.kotlinOptions(configure: Action<KotlinJvmOptions>) =
    (this as ExtensionAware).extensions.findByType(KotlinJvmOptions::class.java)?.let {
        configure.execute(it)
    }

private fun BaseExtension.kotlin(configure: Action<KotlinAndroidProjectExtension>) =
    (this as ExtensionAware).extensions.findByType(KotlinAndroidProjectExtension::class.java)?.let {
        configure.execute(it)
    }

private val Project.android
    get() = extensions.getByType(BaseAppModuleExtension::class.java)

private val Project.androidComponents
    get() = extensions.getByType(ApplicationAndroidComponentsExtension::class.java)

fun Project.setupCommon() {
    androidBase {
        compileSdkVersion(33)
        buildToolsVersion = "33.0.1"
        ndkPath = "$sdkDirectory/ndk/magisk"

        defaultConfig {
            minSdk = 21
            targetSdk = 33
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }

        kotlinOptions {
            jvmTarget = "17"
        }

        kotlin {
            jvmToolchain(17)
        }
    }
}

private fun ApkSigningConfig.getPrivateKey(): KeyStore.PrivateKeyEntry {
    val keyStore = KeyStore.getInstance(storeType ?: KeyStore.getDefaultType())
    storeFile!!.inputStream().use {
        keyStore.load(it, storePassword!!.toCharArray())
    }
    val keyPwdArray = keyPassword!!.toCharArray()
    val entry = keyStore.getEntry(keyAlias!!, KeyStore.PasswordProtection(keyPwdArray))
    return entry as KeyStore.PrivateKeyEntry
}

abstract class AddCommentTask: DefaultTask() {
    @get:Input
    abstract val comment: Property<String>

    @get:InputFiles
    abstract val apkFolder: DirectoryProperty

    @get:OutputDirectory
    abstract val outFolder: DirectoryProperty

    @get:Internal
    abstract val transformationRequest: Property<ArtifactTransformationRequest<AddCommentTask>>

    @get:Internal
    abstract val storeType: Property<String>

    @get:Internal
    abstract val storeFile: Property<File>

    @get:Internal
    abstract val storePassword: Property<String>

    @get:Internal
    abstract val keyPassword: Property<String>

    @get:Internal
    abstract val keyAlias: Property<String>

    @TaskAction
    fun taskAction() = transformationRequest.get().submit(this) { artifact ->
        val inFile = File(artifact.outputFile)
        val outFile = outFolder.file(inFile.name).get().asFile

        val certificateInfo = KeystoreHelper.getCertificateInfo(
            storeType.get(), storeFile.get(), storePassword.get(), keyPassword.get(), keyAlias.get()
        )
        val signingOptions = SigningOptions.builder()
            .setMinSdkVersion(0)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setKey(certificateInfo.key)
            .setCertificates(certificateInfo.certificate)
            .setValidation(SigningOptions.Validation.ASSUME_INVALID)
            .build()
        val options = ZFileOptions().apply {
            noTimestamps = true
            autoSortFiles = true
        }
        outFile.parentFile.mkdirs()
        inFile.copyTo(outFile, overwrite = true)
        ZFiles.apk(outFile, options).use {
            SigningExtension(signingOptions).register(it)
            it.eocdComment = comment.get().toByteArray()
            it.get(IncrementalPackager.APP_METADATA_ENTRY_PATH)?.delete()
            it.get(JarFile.MANIFEST_NAME)?.delete()
        }

        outFile
    }
}

private fun Project.setupAppCommon() {
    setupCommon()
    val configProvider = gradle.sharedServices.registrations.getByName("config").service as Provider<ConfigService>
    android {
        signingConfigs {
            create("config") {
                val config = configProvider.get()
                config["keyStore"]?.also {
                    storeFile = rootProject.file(it)
                    storePassword = config["keyStorePass"]
                    keyAlias = config["keyAlias"]
                    keyPassword = config["keyPass"]
                }
            }
        }

        buildTypes {
            signingConfigs["config"].also {
                debug {
                    signingConfig = if (it.storeFile?.exists() == true) it
                    else signingConfigs["debug"]
                }
                release {
                    signingConfig = if (it.storeFile?.exists() == true) it
                    else signingConfigs["debug"]
                }
            }
        }

        lint {
            disable += "MissingTranslation"
            checkReleaseBuilds = false
        }

        dependenciesInfo {
            includeInApk = false
        }

        buildFeatures {
            buildConfig = true
        }
    }

    androidComponents.onVariants { variant ->
        val commentTask = tasks.register(
            "comment${variant.name.replaceFirstChar { it.uppercase() }}",
            AddCommentTask::class.java
        )
        val transformationRequest = variant.artifacts.use(commentTask)
            .wiredWithDirectories(AddCommentTask::apkFolder, AddCommentTask::outFolder)
            .toTransformMany(SingleArtifact.APK)
        val signingConfig = android.buildTypes.getByName(variant.buildType!!).signingConfig!!
        commentTask.configure {
            this.transformationRequest.set(transformationRequest)
            this.storeType.set(signingConfig.storeType)
            this.storeFile.set(signingConfig.storeFile)
            this.storePassword.set(signingConfig.storePassword)
            this.keyPassword.set(signingConfig.keyPassword)
            this.keyAlias.set(signingConfig.keyAlias)
            this.comment.set("version=${configProvider.get().version}\n" +
                "versionCode=${configProvider.get().versionCode}\n" +
                "stubVersion=${configProvider.get().stubVersion}\n")
            this.outFolder.set(File(buildDir, "outputs/apk/${variant.name}"))
        }
    }
}

fun Project.setupApp() {
    setupAppCommon()
    val configProvider = gradle.sharedServices.registrations.getByName("config").service as Provider<ConfigService>
    val syncLibs by tasks.registering(Sync::class) {
        into("src/main/jniLibs")
        into("armeabi-v7a") {
            from(rootProject.file("native/out/armeabi-v7a")) {
                include("busybox", "magiskboot", "magiskinit", "magiskpolicy", "magisk")
                rename { if (it == "magisk") "libmagisk32.so" else "lib$it.so" }
            }
        }
        into("x86") {
            from(rootProject.file("native/out/x86")) {
                include("busybox", "magiskboot", "magiskinit", "magiskpolicy", "magisk")
                rename { if (it == "magisk") "libmagisk32.so" else "lib$it.so" }
            }
        }
        into("arm64-v8a") {
            from(rootProject.file("native/out/arm64-v8a")) {
                include("busybox", "magiskboot", "magiskinit", "magiskpolicy", "magisk")
                rename { if (it == "magisk") "libmagisk64.so" else "lib$it.so" }
            }
        }
        into("x86_64") {
            from(rootProject.file("native/out/x86_64")) {
                include("busybox", "magiskboot", "magiskinit", "magiskpolicy", "magisk")
                rename { if (it == "magisk") "libmagisk64.so" else "lib$it.so" }
            }
        }
        onlyIf {
            if (inputs.sourceFiles.files.size != 20)
                throw StopExecutionException("Please build binaries first! (./build.py binary)")
            true
        }
    }

    val syncResources by tasks.registering(Sync::class) {
        into("src/main/resources/META-INF/com/google/android")
        from(rootProject.file("scripts/update_binary.sh")) {
            rename { "update-binary" }
        }
        from(rootProject.file("scripts/flash_script.sh")) {
            rename { "updater-script" }
        }
    }

    android.applicationVariants.all {
        val variantCapped = name.replaceFirstChar { it.uppercase() }

        tasks.getByPath("merge${variantCapped}JniLibFolders").dependsOn(syncLibs)
        processJavaResourcesProvider.configure { dependsOn(syncResources) }

        val stubTask = tasks.getByPath(":stub:comment$variantCapped")
        val stubApk = stubTask.outputs.files.asFileTree.filter {
            it.name.endsWith(".apk")
        }

        val syncAssets = tasks.register("sync${variantCapped}Assets", Sync::class) {
            dependsOn(stubTask)
            inputs.property("version", configProvider.get().version)
            inputs.property("versionCode", configProvider.get().versionCode)
            into("src/${this@all.name}/assets")
            from(rootProject.file("scripts")) {
                include("util_functions.sh", "boot_patch.sh", "addon.d.sh")
                include("uninstaller.sh", "module_installer.sh")
            }
            from(rootProject.file("tools/bootctl"))
            into("chromeos") {
                from(rootProject.file("tools/futility"))
                from(rootProject.file("tools/keys")) {
                    include("kernel_data_key.vbprivk", "kernel.keyblock")
                }
            }
            from(stubApk) {
                rename { "stub.apk" }
            }
            filesMatching("**/util_functions.sh") {
                filter {
                    it.replace(
                        "#MAGISK_VERSION_STUB",
                        "MAGISK_VER='${configProvider.get().version}'\nMAGISK_VER_CODE=${configProvider.get().versionCode}"
                    )
                }
                filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
            }
        }
        mergeAssetsProvider.configure { dependsOn(syncAssets) }

        val keysDir = rootProject.file("tools/keys")
        val outSrcDir = File(buildDir, "generated/source/keydata/$name")
        val outSrc = File(outSrcDir, "com/topjohnwu/magisk/signing/KeyData.java")

        val genSrcTask = tasks.register("generate${variantCapped}KeyData") {
            inputs.dir(keysDir)
            outputs.file(outSrc)
            doLast {
                genKeyData(keysDir, outSrc)
            }
        }
        registerJavaGeneratingTask(genSrcTask, outSrcDir)
    }
}

interface Injected {
    @get:Inject
    val exec: ExecOperations
}

fun Project.setupStub() {
    setupAppCommon()
    val configProvider = gradle.sharedServices.registrations.getByName("config").service as Provider<ConfigService>
    androidComponents.onVariants { variant ->
        val variantName = variant.name
        val variantCapped = variantName.replaceFirstChar { it.uppercase() }
        val manifestUpdater =
            project.tasks.register("${variantName}ManifestProducer", ManifestUpdater::class.java) {
                dependsOn("generate${variantCapped}ObfuscatedClass")
                applicationId.set(variant.applicationId)
                appClassDir.set(File(buildDir, "generated/source/app/$variantName"))
                factoryClassDir.set(File(buildDir, "generated/source/factory/$variantName"))
                this.config.set(configProvider)
            }
        variant.artifacts.use(manifestUpdater)
            .wiredWithFiles(
                ManifestUpdater::mergedManifest,
                ManifestUpdater::outputManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)
    }

    android.applicationVariants.all {
        val variantCapped = name.replaceFirstChar { it.uppercase() }
        val variantLowered = name.lowercase()
        val outFactoryClassDir = File(buildDir, "generated/source/factory/${variantLowered}")
        val outAppClassDir = File(buildDir, "generated/source/app/${variantLowered}")
        val outResDir = File(buildDir, "generated/source/res/${variantLowered}")
        val aapt = File(android.sdkDirectory, "build-tools/${android.buildToolsVersion}/aapt2")
        val apk = File(buildDir, "intermediates/processed_res/" +
            "${variantLowered}/out/resources-${variantLowered}.ap_")

        val genManifestTask = tasks.register("generate${variantCapped}ObfuscatedClass") {
            outputs.dirs(outFactoryClassDir, outAppClassDir)
            doLast {
                outFactoryClassDir.mkdirs()
                outAppClassDir.mkdirs()
                genStubClasses(configProvider, outFactoryClassDir, outAppClassDir)
            }
        }
        registerJavaGeneratingTask(genManifestTask, outFactoryClassDir, outAppClassDir)

        val processResourcesTask = tasks.named("process${variantCapped}Resources") {
            outputs.dir(outResDir)
            val inject = objects.newInstance(Injected::class.java)
            doLast {
                val apkTmp = File("${apk}.tmp")
                inject.exec.exec {
                    commandLine(aapt, "optimize", "-o", apkTmp, "--collapse-resource-names", apk)
                }

                val bos = ByteArrayOutputStream()
                ZipFile(apkTmp).use { src ->
                    ZipOutputStream(apk.outputStream()).use {
                        it.setLevel(Deflater.BEST_COMPRESSION)
                        it.putNextEntry(ZipEntry("AndroidManifest.xml"))
                        src.getInputStream(src.getEntry("AndroidManifest.xml")).transferTo(it)
                        it.closeEntry()
                    }
                    DeflaterOutputStream(bos, Deflater(Deflater.BEST_COMPRESSION)).use {
                        src.getInputStream(src.getEntry("resources.arsc")).transferTo(it)
                    }
                }
                apkTmp.delete()
                genEncryptedResources(configProvider, bos.toByteArray(), outResDir)
            }
        }

        registerJavaGeneratingTask(processResourcesTask, outResDir)
    }
    // Override optimizeReleaseResources task
    val apk = File(buildDir, "intermediates/processed_res/" +
        "release/out/resources-release.ap_")
    val optRes = File(buildDir, "intermediates/optimized_processed_res/" +
        "release/resources-release-optimize.ap_")
    tasks.whenTaskAdded {
        if (name == "optimizeReleaseResources") {
            doLast { apk.copyTo(optRes, true) }
        }
    }
    tasks.named<Delete>("clean") {
        delete.addAll(listOf("src/debug/AndroidManifest.xml", "src/release/AndroidManifest.xml"))
    }
}
