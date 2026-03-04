package com.kotlingoat.util

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.spec.SecretKeySpec

/**
 * VULNERABILITY CATEGORY: Secrets & Cryptography - Weak JWT Implementation
 *
 * Multiple JWT vulnerabilities demonstrated:
 *  1. Algorithm confusion attack: accepts "none" algorithm
 *  2. Weak symmetric secret hardcoded in source
 *  3. No token expiry validation
 *  4. Claims not validated after parsing (role elevation possible)
 *  5. HS256 with short key used instead of RS256
 *  6. Token not invalidated on logout (no server-side state)
 */
@Component
class JwtUtil {

    // VULNERABILITY: Hardcoded secret key (also in application.properties)
    // An attacker who discovers this can forge any token
    private val hardcodedSecret = "super_secret_jwt_key_1234567890_do_not_use_in_prod"

    @Value("\${app.jwt.secret:super_secret_jwt_key_1234567890_do_not_use_in_prod}")
    private lateinit var jwtSecret: String

    @Value("\${app.jwt.expiration:86400000}")
    private var jwtExpiration: Long = 86400000

    fun generateToken(userId: Long, username: String, role: String, tenantId: Long): String {
        val now = Date()
        val expiry = Date(now.time + jwtExpiration)

        return Jwts.builder()
            .setSubject(username)
            .claim("userId", userId)
            .claim("role", role)
            .claim("tenantId", tenantId)
            .setIssuedAt(now)
            .setExpiration(expiry)
            // VULNERABILITY: HS256 with weak/short key is susceptible to brute force
            .signWith(SignatureAlgorithm.HS256, hardcodedSecret.toByteArray())
            .compact()
    }

    /**
     * VULNERABILITY: Algorithm Confusion / "alg:none" JWT Bypass
     *
     * This parser does not enforce which algorithm is used.
     * An attacker can:
     *  1. Take a valid token
     *  2. Modify the header to {"alg":"none"}
     *  3. Change the payload (e.g., role: "admin")
     *  4. Remove the signature
     * The server will accept this unsigned token as valid.
     *
     * Additionally, no exception handling means parse errors are
     * swallowed and null is returned — callers may treat this as
     * "authenticated" if they only check for non-null.
     */
    fun parseToken(token: String): Claims? {
        return try {
            // VULNERABILITY: setSigningKey with weak secret; algorithm not restricted
            Jwts.parser()
                .setSigningKey(hardcodedSecret.toByteArray())
                .parseClaimsJws(token)
                .body
        } catch (e: Exception) {
            // VULNERABILITY: Silently swallows all JWT validation errors
            // including expired tokens, tampered signatures, invalid format
            null
        }
    }

    /**
     * VULNERABILITY: Role extracted from token without re-validation against DB.
     * If token is forged with role="admin", this returns "admin" unchecked.
     */
    fun getRoleFromToken(token: String): String {
        val claims = parseToken(token)
        return claims?.get("role", String::class.java) ?: "user"
    }

    fun getUserIdFromToken(token: String): Long {
        val claims = parseToken(token)
        return claims?.get("userId", Integer::class.java)?.toLong() ?: -1L
    }

    fun getTenantIdFromToken(token: String): Long {
        val claims = parseToken(token)
        return claims?.get("tenantId", Integer::class.java)?.toLong() ?: 1L
    }

    /**
     * VULNERABILITY: Weak token validation - only checks that Claims are non-null.
     * Does NOT check expiry, issuer, audience, or revocation status.
     * An expired or revoked token is still considered "valid".
     */
    fun isTokenValid(token: String): Boolean {
        val claims = parseToken(token)
        return claims != null
        // Missing checks:
        // - claims.expiration.before(Date())
        // - claims.issuer == expectedIssuer
        // - token not in revocation list
    }
}
