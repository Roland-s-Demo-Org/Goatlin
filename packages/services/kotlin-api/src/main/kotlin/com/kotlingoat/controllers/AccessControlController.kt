package com.kotlingoat.controllers

import com.kotlingoat.models.*
import com.kotlingoat.util.JwtUtil
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

/**
 * VULNERABILITY CATEGORY: Broken Access Control (BOLA / IDOR)
 *
 * This controller demonstrates multiple access control failures:
 *
 *  BOLA (Broken Object Level Authorization):
 *    - Direct object access by ID with no ownership verification
 *    - Any authenticated user can read/modify any other user's resources
 *
 *  IDOR (Insecure Direct Object Reference):
 *    - Sequential numeric IDs make resource enumeration trivial
 *    - No check that the requesting user owns the resource
 *
 *  Cross-Tenant Data Leakage:
 *    - tenantId taken from request body (user-controlled) instead of JWT
 *    - Allows accessing data belonging to other tenants
 *
 *  Improper Access Control:
 *    - Admin-only actions accessible by any authenticated user
 *    - HTTP method confusion (POST to admin endpoint accepts user tokens)
 *    - Mass assignment: user can elevate own role via update endpoint
 */
@RestController
@RequestMapping("/api")
class AccessControlController {

    @Autowired
    lateinit var jwtUtil: JwtUtil

    @PersistenceContext
    lateinit var em: EntityManager

    // ---------------------------------------------------------------
    // BOLA / IDOR: Notes
    // ---------------------------------------------------------------

    /**
     * GET /api/notes/{noteId}
     *
     * VULNERABILITY (IDOR): Returns any note by ID with no ownership check.
     * User A can fetch User B's private notes simply by guessing the note ID.
     *
     * Attack:
     *   GET /api/notes/1    -> victim's private note
     *   GET /api/notes/2    -> another victim's private note
     *   (enumerate sequentially)
     */
    @GetMapping("/notes/{noteId}")
    fun getNote(
        @PathVariable noteId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        // VULNERABILITY: No check that authHeader.userId == note.ownerId
        val note = em.find(Note::class.java, noteId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Note not found"))

        // Private notes returned to ANY authenticated user
        return ResponseEntity.ok(note)
    }

    /**
     * PUT /api/notes/{noteId}
     *
     * VULNERABILITY (BOLA): Any user can update any note by supplying its ID.
     * No check that the authenticated user owns the note being modified.
     *
     * Attack:
     *   PUT /api/notes/5   (with attacker's JWT)
     *   Body: {"title":"hacked","content":"pwned"}
     *   -> Overwrites victim's note
     */
    @PutMapping("/notes/{noteId}")
    fun updateNote(
        @PathVariable noteId: Long,
        @RequestBody request: NoteRequest,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val note = em.find(Note::class.java, noteId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Note not found"))

        // VULNERABILITY: No ownership check
        // Missing: if (note.ownerId != jwtUtil.getUserIdFromToken(token)) return 403
        note.title = request.title
        note.content = request.content
        note.isPrivate = request.isPrivate
        em.merge(note)

        return ResponseEntity.ok(mapOf("message" to "Note updated", "note" to note))
    }

    /**
     * DELETE /api/notes/{noteId}
     *
     * VULNERABILITY (IDOR): Any user can delete any note.
     */
    @DeleteMapping("/notes/{noteId}")
    fun deleteNote(
        @PathVariable noteId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val note = em.find(Note::class.java, noteId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Note not found"))

        // VULNERABILITY: No ownership or role check before deletion
        em.remove(note)
        return ResponseEntity.ok(mapOf("message" to "Note $noteId deleted"))
    }

    // ---------------------------------------------------------------
    // Cross-Tenant Data Leakage
    // ---------------------------------------------------------------

    /**
     * GET /api/tenant/{tenantId}/users
     *
     * VULNERABILITY (Cross-Tenant): tenantId is taken directly from the URL path.
     * An attacker in tenant 1 can query tenant 2's user list by changing the path param.
     *
     * Secure implementation would read tenantId exclusively from the JWT and
     * refuse to serve data for any other tenantId.
     *
     * Attack:
     *   GET /api/tenant/2/users   (attacker is in tenant 1)
     *   -> Returns all users of tenant 2 including their emails and PII
     */
    @GetMapping("/tenant/{tenantId}/users")
    fun getTenantUsers(
        @PathVariable tenantId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        // VULNERABILITY: tenantId from URL, not from authenticated JWT claims
        // The authenticated user's actual tenantId is never checked
        val users = em.createQuery(
            "SELECT u FROM User u WHERE u.tenantId = :tid", User::class.java
        ).setParameter("tid", tenantId).resultList

        return ResponseEntity.ok(mapOf(
            "tenantId" to tenantId,
            // VULNERABILITY: Full user objects including SSN, credit card returned
            "users" to users
        ))
    }

    /**
     * GET /api/tenant/{tenantId}/notes
     *
     * VULNERABILITY (Cross-Tenant): Fetches all notes for a given tenant
     * without verifying the requestor belongs to that tenant.
     */
    @GetMapping("/tenant/{tenantId}/notes")
    fun getTenantNotes(
        @PathVariable tenantId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val notes = em.createQuery(
            "SELECT n FROM Note n WHERE n.tenantId = :tid", Note::class.java
        ).setParameter("tid", tenantId).resultList

        return ResponseEntity.ok(mapOf("tenantId" to tenantId, "notes" to notes))
    }

    // ---------------------------------------------------------------
    // IDOR: User Profile
    // ---------------------------------------------------------------

    /**
     * GET /api/users/{userId}
     *
     * VULNERABILITY (IDOR): Any user can retrieve any other user's full profile,
     * including SSN, credit card number, CVV, and password hash.
     *
     * Attack:
     *   GET /api/users/1  -> admin's profile with all PII
     *   GET /api/users/2  -> another user's profile
     */
    @GetMapping("/users/{userId}")
    fun getUserProfile(
        @PathVariable userId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val user = em.find(User::class.java, userId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "User not found"))

        // VULNERABILITY: No check that requester's ID == userId
        // VULNERABILITY: Full PII including SSN and credit card returned
        return ResponseEntity.ok(mapOf(
            "id" to user.id,
            "username" to user.username,
            "email" to user.email,
            "role" to user.role,
            "tenantId" to user.tenantId,
            "ssn" to user.ssn,
            "creditCardNumber" to user.creditCardNumber,
            "cvv" to user.cvv,
            "creditBalance" to user.creditBalance,
            // VULNERABILITY: Password exposed in response
            "password" to user.password
        ))
    }

    /**
     * PUT /api/users/{userId}
     *
     * VULNERABILITY (Mass Assignment + IDOR):
     *  1. Any user can update any other user's account (IDOR).
     *  2. The role field is accepted from the request body, allowing
     *     privilege escalation: {"role":"admin"} promotes any user to admin.
     *
     * Attack (privilege escalation):
     *   PUT /api/users/3
     *   Body: {"role":"admin"}
     *   -> User 3 is now an admin
     *
     * Attack (account takeover):
     *   PUT /api/users/1
     *   Body: {"password":"newpass"}
     *   -> Admin's password changed by regular user
     */
    @PutMapping("/users/{userId}")
    fun updateUserProfile(
        @PathVariable userId: Long,
        @RequestBody updates: Map<String, Any>,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val user = em.find(User::class.java, userId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "User not found"))

        // VULNERABILITY: Mass assignment - all fields accepted from user input
        // including sensitive/privileged fields like role, tenantId, isActive
        updates["username"]?.let { user.username = it.toString() }
        updates["email"]?.let { user.email = it.toString() }
        updates["password"]?.let { user.password = it.toString() } // no hashing
        // VULNERABILITY: Role can be set by any user (privilege escalation)
        updates["role"]?.let { user.role = it.toString() }
        // VULNERABILITY: Users can change their own tenantId (cross-tenant)
        updates["tenantId"]?.let { user.tenantId = it.toString().toLong() }
        updates["creditBalance"]?.let { user.creditBalance = it.toString().toDouble() }

        em.merge(user)
        return ResponseEntity.ok(mapOf("message" to "User updated", "user" to user))
    }

    // ---------------------------------------------------------------
    // Function-Level Access Control
    // ---------------------------------------------------------------

    /**
     * DELETE /api/users/{userId}
     *
     * VULNERABILITY (Improper Access Control): Admin-only operation exposed
     * without any role check. Any authenticated user can delete any account.
     *
     * Attack:
     *   DELETE /api/users/1   (with regular user token)
     *   -> Admin account deleted
     */
    @DeleteMapping("/users/{userId}")
    fun deleteUser(
        @PathVariable userId: Long,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        // VULNERABILITY: No role check - should require admin role
        // VULNERABILITY: No check that user isn't deleting themselves (admin)
        val user = em.find(User::class.java, userId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "User not found"))

        em.remove(user)
        return ResponseEntity.ok(mapOf("message" to "User $userId deleted"))
    }

    /**
     * GET /api/users
     *
     * VULNERABILITY: Full user directory exposed to any caller (no auth required).
     * Returns all users across all tenants with full PII.
     */
    @GetMapping("/users")
    fun getAllUsers(): ResponseEntity<Any> {
        // VULNERABILITY: No authentication check, no tenant filtering
        val users = em.createQuery("SELECT u FROM User u", User::class.java).resultList
        return ResponseEntity.ok(mapOf(
            "count" to users.size,
            // VULNERABILITY: Includes passwords, SSNs, credit card data
            "users" to users
        ))
    }

    /**
     * POST /api/users/{userId}/transfer
     *
     * VULNERABILITY (BOLA + Business Logic):
     *  1. Any user can initiate a transfer from any other user's account (BOLA).
     *  2. No balance validation - can transfer more than available balance (negative balance).
     *  3. No CSRF protection.
     *
     * Attack:
     *   POST /api/users/1/transfer
     *   Body: {"toAccountId": 99, "amount": 1000000}
     *   -> Drains victim's account
     */
    @PostMapping("/users/{userId}/transfer")
    fun transferFunds(
        @PathVariable userId: Long,
        @RequestBody request: TransferRequest,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val fromUser = em.find(User::class.java, userId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Source user not found"))
        val toUser = em.find(User::class.java, request.toAccountId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Destination user not found"))

        // VULNERABILITY: No ownership check - any user can drain any account
        // VULNERABILITY: No balance check - allows negative balances
        fromUser.creditBalance -= request.amount
        toUser.creditBalance += request.amount

        em.merge(fromUser)
        em.merge(toUser)

        return ResponseEntity.ok(mapOf(
            "message" to "Transfer complete",
            "fromBalance" to fromUser.creditBalance,
            "toBalance" to toUser.creditBalance
        ))
    }
}
