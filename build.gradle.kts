import java.util.Properties

plugins {
    id("java")
}

group = "net.xagentai"
version = "0.2.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Burp Suite Montoya API — provided by Burp at runtime, not shipped in the JAR.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")

    // JSON serialization — shipped inside the extension JAR (fat JAR).
    implementation("com.google.code.gson:gson:2.15.0")

    // Markdown → HTML rendering for the AI response dialog.
    implementation("org.commonmark:commonmark:0.32.0")

    // Tests
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    archiveBaseName.set("xagentai-burp-ai")

    manifest {
        attributes(
            "Extension-Name" to "Artificial Intelligence for Burp Suite - XagentAI",
            "Extension-Version" to project.version.toString(),
            "Author" to "xagentai.net",
            "Author-URI" to "https://xagentai.net",
            "Implementation-Title" to "Artificial Intelligence for Burp Suite - XagentAI",
            "Implementation-Version" to project.version.toString()
        )
    }

    // Fat JAR: bundle runtime dependencies (Gson) inside the extension JAR.
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    // Strip signatures from shaded JARs to avoid "Invalid signature file digest" at runtime.
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.register<Copy>("packageForBurp") {
    description = "Copy the built fat JAR to dist/ with a clean, versioned name for distribution."
    group = "distribution"
    dependsOn(tasks.jar)
    from(tasks.jar.flatMap { it.archiveFile })
    into(layout.projectDirectory.dir("dist"))
    rename { "xagentai-burp-ai-${project.version}.jar" }
}

// ---------------------------------------------------------------------------
// Local developer install: copy the freshly-built JAR to a folder Burp Suite
// already watches, so reloading the extension becomes a single click.
//
// Configure the destination in `gradle.properties.local` (gitignored):
//     burp.plugins.dir=/absolute/path/to/your/burp-plugins
// Or ad-hoc:  ./gradlew build -Pburp.plugins.dir=/some/path
// ---------------------------------------------------------------------------

val localProps: Properties by lazy {
    val props = Properties()
    file("gradle.properties.local").takeIf { it.exists() }?.inputStream()?.use { s -> props.load(s) }
    props
}

val burpPluginsDir: String? =
    (project.findProperty("burp.plugins.dir") as String?)
        ?: localProps.getProperty("burp.plugins.dir")

tasks.register<Copy>("installToBurp") {
    description = "Copy the built fat JAR to the local Burp plugins folder (burp.plugins.dir)."
    group = "distribution"
    dependsOn(tasks.jar)
    onlyIf {
        if (burpPluginsDir == null) {
            logger.lifecycle("installToBurp skipped: set burp.plugins.dir in gradle.properties.local to enable.")
            false
        } else true
    }
    from(tasks.jar.flatMap { it.archiveFile })
    into(burpPluginsDir ?: "build/libs")
    rename { "xagentai-burp-ai-${project.version}.jar" }
    doLast {
        logger.lifecycle("Installed to: ${burpPluginsDir}/xagentai-burp-ai-${project.version}.jar")
    }
}

// Auto-install after every `build` when burp.plugins.dir is configured.
tasks.named("build") {
    finalizedBy(tasks.named("installToBurp"))
}
