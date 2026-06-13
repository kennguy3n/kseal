package io.kseal.gradle.tasks

import java.io.File
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class GenerateMasvsReportTaskTest {

    @Test
    fun `command line wires manifest, catalog and outputs`() {
        val project = ProjectBuilder.builder().build()
        val task = project.tasks.create("ksealMasvsReport", GenerateMasvsReportTask::class.java)

        val manifest = File(project.projectDir, "manifest.json")
        val catalog = File(project.projectDir, "masvs.md")
        val md = File(project.projectDir, "out/masvs-evidence.md")
        val json = File(project.projectDir, "out/masvs-evidence.json")

        task.executable.set("/opt/masvs-report")
        task.manifestFile.set(manifest)
        task.catalogFile.set(catalog)
        task.reportMarkdownFile.set(md)
        task.reportJsonFile.set(json)

        assertEquals(
            listOf(
                "/opt/masvs-report",
                "-manifest", manifest.absolutePath,
                "-catalog", catalog.absolutePath,
                "-out-md", md.absolutePath,
                "-out-json", json.absolutePath,
            ),
            task.commandLine(),
        )
    }

    @Test
    fun `command line appends extra args`() {
        val project = ProjectBuilder.builder().build()
        val task = project.tasks.create("ksealMasvsReport", GenerateMasvsReportTask::class.java)
        task.executable.set("masvs-report")
        task.manifestFile.set(File(project.projectDir, "m.json"))
        task.catalogFile.set(File(project.projectDir, "c.md"))
        task.reportMarkdownFile.set(File(project.projectDir, "r.md"))
        task.reportJsonFile.set(File(project.projectDir, "r.json"))
        task.extraArgs.set(listOf("--strict"))

        assertEquals("--strict", task.commandLine().last())
    }
}
