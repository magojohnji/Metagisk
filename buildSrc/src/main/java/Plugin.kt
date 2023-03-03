import org.eclipse.jgit.internal.storage.file.FileRepository
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
import java.io.File
import java.util.*

abstract class ConfigService: BuildService<ConfigService.Params> {
    val commitHash: String

    val random: Random

    val props: Properties

    val version: String get() = get("version") ?: commitHash

    val versionCode: Int get() = get("magisk.versionCode")!!.toInt()

    val stubVersion: String get() = get("magisk.stubVersion")!!

    internal interface Params : BuildServiceParameters {
        val gitDir: DirectoryProperty
        val gradleProperties: RegularFileProperty
        val configProp: RegularFileProperty
        val configPath: Property<String>
    }

    operator fun get(key: String): String? {
        val v = props[key] as? String ?: return null
        return v.ifBlank { null }
    }

    init {
        val repo = FileRepository(parameters.gitDir.get().asFile)
        val refId = repo.refDatabase.exactRef("HEAD").objectId
        commitHash = repo.newObjectReader().abbreviate(refId, 8).name()
        val seed = if (System.getenv("CI") != null) 42 else commitHash.hashCode()
        random = Random(seed.toLong())
        props = Properties()
        parameters.gradleProperties.get().asFile.inputStream().use { props.load(it) }
        val config = parameters.configPath.orNull?.let { File(it) } ?: parameters.configProp.asFile.get()
        if (config.exists())
            config.inputStream().use { props.load(it) }
        println("Commit hash: $commitHash")
    }
}
class MagiskPlugin : Plugin<Project> {
    override fun apply(project: Project) = project.applyPlugin()

    private fun Project.applyPlugin() {
        val config = gradle.sharedServices.registerIfAbsent("config", ConfigService::class.java) {
            parameters.gitDir.set(rootProject.file(".git"))
            parameters.configProp.set(rootProject.file("config.prop"))
            parameters.gradleProperties.set(rootProject.file("gradle.properties"))
            parameters.configPath.set(providers.gradleProperty("configPath"))
        }
        initRandom(config.get(), rootProject.file("dict.txt"))
    }
}
