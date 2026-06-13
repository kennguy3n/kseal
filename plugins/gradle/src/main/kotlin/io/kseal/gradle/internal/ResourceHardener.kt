package io.kseal.gradle.internal

import java.io.ByteArrayInputStream
import java.io.StringWriter
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Element

/**
 * R8-aware string-resource obfuscation.
 *
 * Android `res/values.../strings.xml` `<string>` **values** are sealed with an
 * AES-256-GCM key derived from the per-build polymorphism seed; the plaintext in
 * the resource table is replaced by an opaque, seed-permuted token that the kseal
 * SDK resolves at runtime. Resource **names** (keys) are never renamed — they map
 * to aapt resource ids and renaming them would break resource shrinking and
 * `getIdentifier` lookups — so the transform is safe for R8 resource shrinking.
 *
 * Two safety rails ensure the app keeps working:
 *  - any key matched by a keep rule / keep-glob is left in plaintext, and
 *  - any value that *looks like* a reflection target (a fully-qualified class
 *    name) is left in plaintext, because it may be fed to `Class.forName`.
 *
 * Output is deterministic for a given (inputs, seed) pair so the owning task
 * stays cacheable and reproducible.
 */
internal object ResourceHardener {

    private const val SEAL_LABEL = "string-resource-seal"
    private val FQCN = Regex("^[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)+$")

    data class ResFile(val relativePath: String, val content: String)

    data class Result(
        val transformedFiles: Map<String, String>,
        val sealedBlob: ByteArray,
        val tokenToKey: Map<String, String>,
        val sealedCount: Int,
        val keptCount: Int,
    )

    fun harden(files: List<ResFile>, keep: KeepRules, seed: ByteArray): Result {
        val key = Crypto.deriveKey(seed, SEAL_LABEL)
        val tokenKey = Crypto.deriveKey(seed, "string-resource-token")

        val transformed = LinkedHashMap<String, String>()
        val sealedValues = LinkedHashMap<String, String>() // token -> plaintext value
        val tokenToKey = LinkedHashMap<String, String>()    // token -> resource key
        var keptCount = 0

        for (file in files.sortedBy { it.relativePath }) {
            val doc = parse(file.content)
            val strings = doc.getElementsByTagName("string")
            for (n in 0 until strings.length) {
                val el = strings.item(n) as? Element ?: continue
                val name = el.getAttribute("name")
                if (name.isBlank()) continue
                val value = el.textContent
                if (shouldKeep(name, value, keep)) {
                    keptCount++
                    continue
                }
                val token = tokenFor(tokenKey, name)
                sealedValues[token] = value
                tokenToKey[token] = name
                el.textContent = token
            }
            transformed[file.relativePath] = serialize(doc)
        }

        val sealedJson = Json.write(sealedValues, indent = false).toByteArray()
        // Bind the deterministic nonce to the sealed content (not just the label):
        // with a pinned explicit seed the key is constant across builds, so a
        // content-independent context could reuse a (key, nonce) pair on changed
        // resources. Hashing the plaintext keeps output reproducible for identical
        // content while guaranteeing distinct nonces for distinct content.
        val sealedBlob = Crypto.seal(key, sealedJson, nonceContext = "$SEAL_LABEL:${Crypto.sha256Hex(sealedJson)}")

        return Result(
            transformedFiles = transformed,
            sealedBlob = sealedBlob,
            tokenToKey = tokenToKey,
            sealedCount = sealedValues.size,
            keptCount = keptCount,
        )
    }

    private fun shouldKeep(name: String, value: String, keep: KeepRules): Boolean =
        keep.keepsName(name) || FQCN.matches(value.trim())

    /** Stable per-seed opaque token; distinct seeds permute the token space. */
    private fun tokenFor(tokenKey: ByteArray, resourceKey: String): String {
        val mac = Crypto.hmacSha256(tokenKey, resourceKey.toByteArray())
        return "kseal_" + Crypto.hex(mac).substring(0, 16)
    }

    private fun parse(xml: String): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance().apply {
            setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            isExpandEntityReferences = false
        }
        return factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
    }

    private fun serialize(doc: org.w3c.dom.Document): String {
        val tf = TransformerFactory.newInstance().newTransformer().apply {
            setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
            setOutputProperty(OutputKeys.ENCODING, "UTF-8")
            setOutputProperty(OutputKeys.INDENT, "no")
        }
        val writer = StringWriter()
        tf.transform(DOMSource(doc), StreamResult(writer))
        return writer.toString()
    }
}
