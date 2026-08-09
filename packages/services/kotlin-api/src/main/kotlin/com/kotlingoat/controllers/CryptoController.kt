package com.kotlingoat.controllers

import com.kotlingoat.models.User
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * VULNERABILITY CATEGORY: Secrets & Cryptography
 *
 * Vulnerabilities demonstrated:
 *  1. Hardcoded credentials and API keys
 *  2. Weak hashing algorithms (MD5, SHA1 for passwords)
 *  3. Unsalted password hashing (rainbow table attacks)
 *  4. Weak symmetric encryption (ECB mode, short keys)
 *  5. Sensitive data stored in plain text
 *  6. Cryptographic key derived from predictable value
 *  7. Base64 used as "encryption" (encoding is not encryption)
 *  8. Sensitive data exposed in logs and error messages
 *  9. Weak random number generation for security tokens
 * 10. Plaintext secrets in application.properties
 */
@RestController
@RequestMapping("/api/crypto")
class CryptoController {

    @PersistenceContext
    lateinit var em: EntityManager

    // ---------------------------------------------------------------
    // Hardcoded Credentials
    // ---------------------------------------------------------------

    // VULNERABILITY: All of these are hardcoded secrets in source code
    // They will be committed to version control and accessible to anyone
    // who can access the repository.
    companion object {
        // VULNERABILITY: Hardcoded admin credentials
        const val ADMIN_USERNAME = "admin"
        const val ADMIN_PASSWORD = "Admin@KotlinGoat2024!"

        // VULNERABILITY: Hardcoded database credentials
        const val DB_HOST = "db.internal.kotlingoat.com"
        const val DB_PORT = 5432
        const val DB_NAME = "kotlingoat_prod"
        const val DB_USER = "kotlingoat_admin"
        const val DB_PASSWORD = "Sup3rS3cr3tDBP@ss!"

        // VULNERABILITY: Hardcoded API keys
        const val OPENAI_API_KEY = "sk-proj-abc123hardcodedkeydonotcommit"
        const val STRIPE_SECRET_KEY = "sk_live_hardcoded_stripe_key_abc123"
        const val SENDGRID_API_KEY = "SG.hardcoded_sendgrid_key_abc123456"
        const val TWILIO_AUTH_TOKEN = "hardcoded_twilio_token_abc123"
        const val AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
        const val AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        // VULNERABILITY: Hardcoded encryption key (symmetric)
        const val AES_KEY = "1234567890123456"  // 16-byte key, trivially guessable

        // VULNERABILITY: Hardcoded JWT signing secret
        const val JWT_SECRET = "super_secret_jwt_key_1234567890_do_not_use_in_prod"

        // VULNERABILITY: Hardcoded internal service URLs
        const val INTERNAL_API_URL = "http://internal-api.corp:8080/v1"
        const val PAYMENT_GATEWAY_URL = "http://payments.internal:9090"
    }

    /**
     * GET /api/crypto/config
     *
     * VULNERABILITY (Sensitive Data Exposure):
     * Returns application configuration including hardcoded secrets.
     * No authentication required on this endpoint.
     */
    @GetMapping("/config")
    fun getConfig(): ResponseEntity<Any> {
        return ResponseEntity.ok(mapOf(
            "database" to mapOf(
                "host" to DB_HOST,
                "port" to DB_PORT,
                "name" to DB_NAME,
                "user" to DB_USER,
                // VULNERABILITY: DB password returned in API response
                "password" to DB_PASSWORD
            ),
            "apis" to mapOf(
                "openai" to OPENAI_API_KEY,
                "stripe" to STRIPE_SECRET_KEY,
                "aws" to mapOf("access" to AWS_ACCESS_KEY, "secret" to AWS_SECRET_KEY)
            ),
            "jwt" to mapOf("secret" to JWT_SECRET),
            "encryption" to mapOf("aesKey" to AES_KEY)
        ))
    }

    // ---------------------------------------------------------------
    // Weak Hashing
    // ---------------------------------------------------------------

    /**
     * POST /api/crypto/hash?algorithm=...
     *
     * VULNERABILITY (Weak Hashing Algorithms):
     * MD5 and SHA1 are cryptographically broken for password storage.
     * Additionally, hashes are unsalted, enabling rainbow table attacks.
     *
     * Attack: Precomputed rainbow tables can crack MD5/SHA1 hashes instantly.
     * e.g., MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
     *       -> instantly found in any rainbow table
     */
    @PostMapping("/hash")
    fun hashValue(
        @RequestBody body: Map<String, String>,
        @RequestParam(defaultValue = "MD5") algorithm: String
    ): ResponseEntity<Any> {
        val value = body["value"] ?: return ResponseEntity.badRequest().build()

        // VULNERABILITY: MD5 and SHA1 are broken for cryptographic use
        // VULNERABILITY: No salt added - enables rainbow table / precomputed attacks
        val digest = MessageDigest.getInstance(algorithm)  // MD5, SHA1, SHA256 accepted
        val hash = digest.digest(value.toByteArray())
        val hexHash = hash.joinToString("") { "%02x".format(it) }

        return ResponseEntity.ok(mapOf(
            "algorithm" to algorithm,
            "input" to value,
            "hash" to hexHash,
            "note" to "No salt used - vulnerable to rainbow tables",
            "vulnerability" to when (algorithm.uppercase()) {
                "MD5" -> "MD5 is cryptographically broken - collisions found, do not use for security"
                "SHA1" -> "SHA1 is deprecated for security use - collision attacks demonstrated"
                else -> "Even SHA256 without salt is vulnerable to rainbow tables for passwords"
            }
        ))
    }

    /**
     * POST /api/crypto/hash-password
     *
     * VULNERABILITY (Unsalted Weak Hash for Password Storage):
     * Passwords stored as plain MD5 hashes without salt.
     * Any password in a rainbow table is immediately cracked.
     */
    @PostMapping("/hash-password")
    fun hashPassword(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val password = body["password"] ?: return ResponseEntity.badRequest().build()

        // VULNERABILITY: MD5 without salt for password storage
        // Secure alternative: BCrypt, Argon2, or scrypt with high work factor
        val md5 = MessageDigest.getInstance("MD5")
        val hashedPassword = md5.digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

        // VULNERABILITY: Also computing SHA1 (equally weak)
        val sha1 = MessageDigest.getInstance("SHA1")
        val sha1Password = sha1.digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

        return ResponseEntity.ok(mapOf(
            "plaintext" to password,       // VULNERABILITY: Echoing plaintext password
            "md5" to hashedPassword,
            "sha1" to sha1Password,
            "base64" to Base64.getEncoder().encodeToString(password.toByteArray()),  // Not encryption!
            "note" to "These are all weak - use BCrypt or Argon2 in production"
        ))
    }

    // ---------------------------------------------------------------
    // Weak Encryption
    // ---------------------------------------------------------------

    /**
     * POST /api/crypto/encrypt
     *
     * VULNERABILITY (Weak Encryption - AES-ECB mode):
     * ECB (Electronic Code Book) mode is deterministic and reveals
     * plaintext patterns. Identical plaintext blocks produce identical
     * ciphertext blocks, breaking confidentiality.
     *
     * VULNERABILITY: Hardcoded key "1234567890123456" is trivially guessable.
     * VULNERABILITY: No IV (initialization vector) used.
     * VULNERABILITY: No authentication tag (unauthenticated encryption).
     */
    @PostMapping("/encrypt")
    fun encryptData(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val plaintext = body["data"] ?: return ResponseEntity.badRequest().build()
        val keyStr = body["key"] ?: AES_KEY  // Falls back to hardcoded key

        return try {
            // VULNERABILITY: AES in ECB mode - deterministic, no diffusion between blocks
            val keySpec = SecretKeySpec(keyStr.toByteArray(Charsets.UTF_8).take(16).toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")  // ECB is insecure
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)

            val encrypted = cipher.doFinal(plaintext.toByteArray())
            val encryptedBase64 = Base64.getEncoder().encodeToString(encrypted)

            ResponseEntity.ok(mapOf(
                "plaintext" to plaintext,
                "ciphertext" to encryptedBase64,
                "mode" to "AES-ECB (INSECURE)",
                "key" to keyStr,             // VULNERABILITY: Key returned in response
                "vulnerabilities" to listOf(
                    "ECB mode reveals plaintext patterns",
                    "Hardcoded key stored in source code",
                    "No IV - encryption is deterministic",
                    "No authentication tag - ciphertext malleable"
                )
            ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf("error" to e.message))
        }
    }

    /**
     * POST /api/crypto/decrypt
     *
     * VULNERABILITY: Decryption endpoint accessible to anyone.
     * An attacker who knows the hardcoded key can decrypt any ciphertext.
     */
    @PostMapping("/decrypt")
    fun decryptData(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val ciphertext = body["data"] ?: return ResponseEntity.badRequest().build()
        val keyStr = body["key"] ?: AES_KEY

        return try {
            val keySpec = SecretKeySpec(keyStr.toByteArray(Charsets.UTF_8).take(16).toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, keySpec)

            val decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext))

            ResponseEntity.ok(mapOf(
                "decrypted" to String(decrypted),
                "key" to keyStr
            ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf("error" to e.message))
        }
    }

    /**
     * GET /api/crypto/users/passwords
     *
     * VULNERABILITY (Sensitive Data Exposure):
     * Endpoint returns all user passwords in plain text.
     * No authentication required.
     */
    @GetMapping("/users/passwords")
    fun getAllPasswords(): ResponseEntity<Any> {
        // VULNERABILITY: Returns all user credentials with no auth check
        val users = em.createQuery("SELECT u FROM User u", User::class.java).resultList
        return ResponseEntity.ok(mapOf(
            "users" to users.map { u ->
                mapOf(
                    "id" to u.id,
                    "username" to u.username,
                    // VULNERABILITY: Plaintext passwords returned in API response
                    "password" to u.password,
                    "email" to u.email,
                    "ssn" to u.ssn,
                    "creditCard" to u.creditCardNumber
                )
            }
        ))
    }
}
