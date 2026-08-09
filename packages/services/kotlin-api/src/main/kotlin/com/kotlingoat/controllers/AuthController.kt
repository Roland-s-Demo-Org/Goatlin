package com.kotlingoat.controllers

import com.kotlingoat.models.*
import com.kotlingoat.util.JwtUtil
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.*

/**
 * VULNERABILITY CATEGORY: Authentication & Session Management
 *
 * Vulnerabilities demonstrated in this controller:
 *  1. No rate limiting / brute force protection on /login
 *  2. Passwords stored and compared in plain text
 *  3. Predictable password reset tokens (UUID is not secret enough here)
 *  4. Password reset token never expires
 *  5. Insecure cookie attributes (no HttpOnly, no Secure, no SameSite)
 *  6. JWT placed in localStorage-accessible header with no cookie binding
 *  7. Username enumeration via different error messages
 *  8. No account lockout after failed attempts
 *  9. Session token not invalidated on logout (server-side)
 * 10. SQL injection in login query (demonstrated in InjectionController too)
 */
@RestController
@RequestMapping("/api/auth")
class AuthController {

    @Autowired
    lateinit var jwtUtil: JwtUtil

    @PersistenceContext
    lateinit var em: EntityManager

    // VULNERABILITY: In-memory token store with no expiry enforcement
    private val resetTokens = mutableMapOf<String, Long>()  // token -> userId

    /**
     * POST /api/auth/login
     *
     * VULNERABILITY 1: No rate limiting - unlimited brute force attempts.
     * VULNERABILITY 2: Plain-text password comparison.
     * VULNERABILITY 3: Username enumeration - different messages for
     *   "user not found" vs "wrong password".
     * VULNERABILITY 4: SQL Injection - username injected directly into query.
     *
     * Example SQLi bypass:
     *   username: admin' OR '1'='1' --
     *   password: anything
     */
    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginRequest,
        response: HttpServletResponse
    ): ResponseEntity<Map<String, Any>> {

        // VULNERABILITY: SQL Injection - raw string concatenation in JPQL/native SQL
        val sql = "SELECT * FROM users WHERE username = '${request.username}' AND password = '${request.password}'"
        val result = em.createNativeQuery(sql, User::class.java).resultList

        if (result.isEmpty()) {
            // VULNERABILITY: Username enumeration - reveals whether user exists
            val userExists = em.createNativeQuery(
                "SELECT * FROM users WHERE username = '${request.username}'",
                User::class.java
            ).resultList.isNotEmpty()

            return if (userExists) {
                ResponseEntity.status(401).body(mapOf("error" to "Invalid password"))
            } else {
                ResponseEntity.status(401).body(mapOf("error" to "User not found"))
            }
        }

        val user = result[0] as User
        val token = jwtUtil.generateToken(user.id, user.username, user.role, user.tenantId)

        // VULNERABILITY: Cookie set without HttpOnly, Secure, or SameSite attributes
        val cookie = Cookie("auth_token", token)
        cookie.path = "/"
        cookie.maxAge = 86400
        // Missing: cookie.isHttpOnly = true  (XSS can steal this cookie)
        // Missing: cookie.secure = true       (sent over HTTP)
        // Missing: SameSite=Strict            (CSRF possible)
        response.addCookie(cookie)

        return ResponseEntity.ok(mapOf(
            "token" to token,
            "userId" to user.id,
            "username" to user.username,
            "role" to user.role,
            // VULNERABILITY: Sensitive data returned unnecessarily
            "email" to user.email,
            "creditCard" to user.creditCardNumber
        ))
    }

    /**
     * POST /api/auth/signup
     *
     * VULNERABILITY: Passwords stored in plain text with no hashing.
     * No password complexity requirements enforced.
     * No email verification required.
     */
    @PostMapping("/signup")
    fun signup(@RequestBody request: SignupRequest): ResponseEntity<Map<String, Any>> {
        // VULNERABILITY: Password stored in plain text
        val user = User(
            username = request.username,
            password = request.password,   // No bcrypt/argon2/etc.
            email = request.email,
            tenantId = request.tenantId,
            role = "user"
        )

        em.persist(user)
        return ResponseEntity.status(201).body(mapOf(
            "message" to "Account created",
            "userId" to user.id,
            // VULNERABILITY: Password echoed back in response
            "password" to user.password
        ))
    }

    /**
     * POST /api/auth/forgot-password
     *
     * VULNERABILITY 1: Predictable reset token (UUID v4 has known weaknesses
     *   when PRNG is weak - demonstrated here with java.util.Random).
     * VULNERABILITY 2: Token never expires.
     * VULNERABILITY 3: Token stored server-side in plaintext.
     * VULNERABILITY 4: Username enumeration - 404 if user doesn't exist.
     */
    @PostMapping("/forgot-password")
    fun forgotPassword(@RequestBody body: Map<String, String>): ResponseEntity<Map<String, Any>> {
        val username = body["username"] ?: return ResponseEntity.badRequest().build()

        val users = em.createNativeQuery(
            "SELECT * FROM users WHERE username = '$username'", User::class.java
        ).resultList

        if (users.isEmpty()) {
            // VULNERABILITY: Reveals that the user doesn't exist
            return ResponseEntity.status(404).body(mapOf("error" to "User not found"))
        }

        val user = users[0] as User

        // VULNERABILITY: Using java.util.Random (predictable) instead of SecureRandom
        val random = Random(System.currentTimeMillis())
        val token = "${random.nextLong()}-${random.nextLong()}"

        // VULNERABILITY: Token stored indefinitely with no expiry
        resetTokens[token] = user.id

        return ResponseEntity.ok(mapOf(
            "message" to "Reset token generated",
            // VULNERABILITY: Reset token returned directly in response (should be emailed)
            "resetToken" to token,
            "userId" to user.id
        ))
    }

    /**
     * POST /api/auth/reset-password
     *
     * VULNERABILITY: Token not invalidated after use (can be reused).
     * VULNERABILITY: New password stored in plain text.
     * VULNERABILITY: No current-password confirmation required.
     */
    @PostMapping("/reset-password")
    fun resetPassword(@RequestBody request: PasswordResetRequest): ResponseEntity<Map<String, Any>> {
        val userId = resetTokens[request.token]
            ?: return ResponseEntity.status(400).body(mapOf("error" to "Invalid token"))

        val user = em.find(User::class.java, userId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "User not found"))

        // VULNERABILITY: New password stored in plain text
        user.password = request.newPassword
        em.merge(user)

        // VULNERABILITY: Token NOT removed after use - can be reused indefinitely
        // resetTokens.remove(request.token)  <- deliberately commented out

        return ResponseEntity.ok(mapOf("message" to "Password reset successfully"))
    }

    /**
     * POST /api/auth/logout
     *
     * VULNERABILITY: Server-side session/token not invalidated.
     * The JWT remains valid until its expiry time even after "logout".
     * An attacker who captured the token can continue using it.
     */
    @PostMapping("/logout")
    fun logout(
        @RequestHeader(value = "Authorization", required = false) authHeader: String?,
        response: HttpServletResponse
    ): ResponseEntity<Map<String, Any>> {
        // VULNERABILITY: Token is NOT added to a revocation list/blacklist
        // The token remains valid for its full lifetime after logout

        // Clear cookie (client-side only - server still accepts the token)
        val cookie = Cookie("auth_token", "")
        cookie.maxAge = 0
        response.addCookie(cookie)

        return ResponseEntity.ok(mapOf("message" to "Logged out (token still valid server-side)"))
    }

    /**
     * GET /api/auth/admin
     *
     * VULNERABILITY: Role check performed only on JWT claim without DB verification.
     * Forging a JWT with role="admin" bypasses this check.
     * No server-side session or DB lookup to confirm actual role.
     */
    @GetMapping("/admin")
    fun adminPanel(
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Map<String, Any>> {
        val token = authHeader?.removePrefix("Bearer ") ?: ""

        // VULNERABILITY: Role taken from JWT claims without DB verification
        val role = jwtUtil.getRoleFromToken(token)
        if (role != "admin") {
            return ResponseEntity.status(403).body(mapOf("error" to "Forbidden"))
        }

        // Return "sensitive" admin data
        val allUsers = em.createNativeQuery("SELECT * FROM users", User::class.java).resultList
        return ResponseEntity.ok(mapOf(
            "message" to "Welcome, admin!",
            // VULNERABILITY: All user records including passwords returned
            "users" to allUsers
        ))
    }
}
