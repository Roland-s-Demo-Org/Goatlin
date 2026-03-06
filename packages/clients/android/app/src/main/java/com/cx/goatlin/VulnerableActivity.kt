package com.cx.goatlin

import android.content.ContentValues
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import com.cx.goatlin.helpers.DatabaseHelper
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * VulnerableActivity - Demonstrates multiple Android-specific security vulnerabilities.
 *
 * VULNERABILITY CATEGORIES DEMONSTRATED:
 *  1. Hardcoded credentials and API keys
 *  2. WebView JavaScript injection (XSS via JavaScript interface)
 *  3. Insecure data storage (plain-text SharedPreferences, SQLite, external storage)
 *  4. Sensitive data in Android logs (LogCat)
 *  5. SQL injection in SQLite query
 *  6. Weak cryptography (MD5, AES-ECB)
 *  7. Unvalidated deep link / intent data (open redirect, command injection)
 *  8. SSRF via WebView URL navigation
 *  9. Exported activities without permission checks
 * 10. Broadcast receiver leaking sensitive data
 * 11. Improper SSL/TLS validation (accept all certificates)
 *
 * This activity is intentionally exported (see AndroidManifest.xml) with no
 * permission requirements, allowing any app on the device to launch it.
 */
class VulnerableActivity : AppCompatActivity() {

    // ---------------------------------------------------------------
    // VULNERABILITY: Hardcoded Credentials
    // ---------------------------------------------------------------
    companion object {
        // VULNERABILITY: Hardcoded credentials in source code
        private const val HARDCODED_API_KEY = "sk-proj-abc123hardcoded"
        private const val HARDCODED_ADMIN_PASSWORD = "Admin@Goat2024!"
        private const val HARDCODED_DB_PASSWORD = "DatabaseP@ss123"

        // VULNERABILITY: Hardcoded encryption key (AES-ECB with predictable key)
        private const val AES_KEY = "GoatAES16ByteKey"

        // VULNERABILITY: Debug backdoor credential
        private const val BACKDOOR_TOKEN = "debug-bypass-auth-AAAA1234"

        // VULNERABILITY: Internal service URL hardcoded
        private const val INTERNAL_API = "http://10.0.2.2:8081/api"
    }

    private lateinit var webView: WebView
    private lateinit var dbHelper: DatabaseHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        dbHelper = DatabaseHelper(this)

        // VULNERABILITY: Log sensitive data (visible in Android logcat)
        Log.d("KotlinGoat", "API Key: $HARDCODED_API_KEY")
        Log.d("KotlinGoat", "Admin password: $HARDCODED_ADMIN_PASSWORD")
        Log.e("KotlinGoat", "User session token: ${getStoredToken()}")

        // Process intent data (deep link)
        handleDeepLink(intent)

        // Setup vulnerable WebView
        setupVulnerableWebView()

        // Demo various vulnerabilities
        demonstrateInsecureStorage()
        demonstrateWeakCrypto()
        demonstrateSqlInjection()
    }

    // ---------------------------------------------------------------
    // VULNERABILITY: Unvalidated Deep Link / Intent Injection
    // ---------------------------------------------------------------

    /**
     * Handles deep links from external apps or browsers.
     *
     * VULNERABILITY (Open Redirect / Intent Injection):
     * The URL parameter from the intent is used directly in WebView navigation
     * without any validation. A malicious app or deep link can navigate
     * the WebView to any URL, including:
     *   - file:///data/data/com.cx.goatlin/shared_prefs/ (LFI)
     *   - http://attacker.com/phishing
     *   - javascript:stealData()
     *
     * Attack via deep link:
     *   kotlingoat://open?url=file:///data/data/com.cx.goatlin/shared_prefs/goatlin_prefs.xml
     *   kotlingoat://open?url=javascript:alert(document.cookie)
     *
     * VULNERABILITY (Path Traversal via intent):
     *   kotlingoat://file?path=../../databases/goatlin.db
     *   -> Reads the app's SQLite database file
     */
    private fun handleDeepLink(intent: Intent?) {
        val data: Uri? = intent?.data

        // VULNERABILITY: No scheme or host validation
        val url = data?.getQueryParameter("url")
        val filePath = data?.getQueryParameter("path")
        val command = data?.getQueryParameter("action")  // VULNERABILITY: "action" parameter

        if (url != null) {
            // VULNERABILITY: Arbitrary URL navigation including file:// and javascript:
            webView.loadUrl(url)
        }

        if (filePath != null) {
            // VULNERABILITY: Path traversal via intent data
            val file = File(filesDir, filePath)  // No canonicalization
            if (file.exists()) {
                Log.d("KotlinGoat", "File content: ${file.readText()}")
            }
        }

        // VULNERABILITY: Command-like action from external intent
        if (command == "export_data") {
            exportUserDataToExternalStorage()
        }
    }

    // ---------------------------------------------------------------
    // VULNERABILITY: WebView Misconfigurations
    // ---------------------------------------------------------------

    /**
     * Sets up a WebView with multiple security vulnerabilities.
     *
     * VULNERABILITY 1: JavaScript enabled with addJavascriptInterface
     *   Any JavaScript in the WebView can call native Android methods.
     *   If the WebView loads attacker-controlled content, RCE is possible.
     *
     * VULNERABILITY 2: File access enabled
     *   JavaScript in the WebView can read local files via XHR/fetch:
     *   fetch('file:///data/data/com.cx.goatlin/shared_prefs/credentials.xml')
     *
     * VULNERABILITY 3: Universal access from file URLs enabled
     *   Allows cross-origin requests from file:// URLs.
     *
     * VULNERABILITY 4: No SSL error handling (accepts invalid certificates)
     */
    private fun setupVulnerableWebView() {
        webView = WebView(this)
        val settings: WebSettings = webView.settings

        // VULNERABILITY: JavaScript enabled
        settings.javaScriptEnabled = true

        // VULNERABILITY: File access allows reading device files from JS
        @Suppress("SetJavaScriptEnabled")
        settings.allowFileAccess = true
        settings.allowContentAccess = true

        // VULNERABILITY: Cross-origin file access
        settings.allowUniversalAccessFromFileURLs = true
        settings.allowFileAccessFromFileURLs = true

        // VULNERABILITY: JavaScript interface - exposes native Android API to JS
        // Any JS running in this WebView can call nativeBridge.* methods
        webView.addJavascriptInterface(NativeBridge(), "nativeBridge")

        // VULNERABILITY: Custom WebViewClient that accepts all SSL certificates
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(
                view: android.webkit.WebView?,
                handler: android.webkit.SslErrorHandler?,
                error: android.net.http.SslError?
            ) {
                // VULNERABILITY: SSL errors silently accepted (MITM attacks possible)
                handler?.proceed()
            }
        }
    }

    /**
     * JavaScript bridge object exposed to WebView JavaScript.
     *
     * VULNERABILITY: Any JavaScript in the WebView (including from attacker-
     * controlled pages) can call these methods to:
     *  - Read device contacts, SMS, files
     *  - Access SharedPreferences (credentials)
     *  - Make network requests
     *  - Execute shell commands (on rooted devices)
     *
     * Attack (from malicious page loaded in WebView):
     *   nativeBridge.getCredentials()  -> returns stored username/password
     *   nativeBridge.readFile("/data/data/com.cx.goatlin/databases/goatlin.db")
     */
    inner class NativeBridge {
        @android.webkit.JavascriptInterface
        fun getCredentials(): String {
            // VULNERABILITY: Returns stored credentials to JavaScript
            val prefs = getSharedPreferences("goatlin_prefs", MODE_PRIVATE)
            return "{\"username\":\"${prefs.getString("username", "")}\",\"password\":\"${prefs.getString("password", "")}\"}"
        }

        @android.webkit.JavascriptInterface
        fun getApiKey(): String {
            // VULNERABILITY: Returns hardcoded API key to JavaScript
            return HARDCODED_API_KEY
        }

        @android.webkit.JavascriptInterface
        fun readFile(path: String): String {
            // VULNERABILITY: Reads arbitrary files from JavaScript
            return try {
                File(path).readText()
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }

        @android.webkit.JavascriptInterface
        fun makeRequest(url: String): String {
            // VULNERABILITY: SSRF via JavaScript bridge - JS can make server-side requests
            return try {
                val connection = URL(url).openConnection() as HttpURLConnection
                connection.inputStream.bufferedReader().readText()
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }
    }

    // ---------------------------------------------------------------
    // VULNERABILITY: Insecure Data Storage
    // ---------------------------------------------------------------

    /**
     * VULNERABILITY: Sensitive data stored in plain-text SharedPreferences.
     * SharedPreferences XML file is readable by other apps on rooted devices
     * and via ADB backup.
     *
     * Location: /data/data/com.cx.goatlin/shared_prefs/goatlin_prefs.xml
     */
    private fun demonstrateInsecureStorage() {
        val prefs = getSharedPreferences("goatlin_prefs", MODE_PRIVATE)
        prefs.edit().apply {
            // VULNERABILITY: Storing credentials in plain-text SharedPreferences
            putString("username", "alice")
            putString("password", "password123")      // Plain text!
            putString("api_key", HARDCODED_API_KEY)
            putString("auth_token", "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.fake")
            putString("credit_card", "4111111111111111")  // PCI-DSS violation
            putString("ssn", "123-45-6789")              // Regulatory violation
            apply()
        }

        // VULNERABILITY: Also logging sensitive data
        Log.d("KotlinGoat", "Stored credentials: alice / password123")
        Log.d("KotlinGoat", "Stored CC: 4111111111111111")
    }

    /**
     * VULNERABILITY: Exporting sensitive data to external storage (world-readable).
     * Files on external storage are accessible to any app with READ_EXTERNAL_STORAGE.
     */
    private fun exportUserDataToExternalStorage() {
        val prefs = getSharedPreferences("goatlin_prefs", MODE_PRIVATE)
        val sensitiveData = """
            username=${prefs.getString("username", "")}
            password=${prefs.getString("password", "")}
            api_key=${prefs.getString("api_key", "")}
            credit_card=${prefs.getString("credit_card", "")}
        """.trimIndent()

        // VULNERABILITY: Writing sensitive data to external storage (world-readable)
        val externalFile = File(getExternalFilesDir(null), "user_data_backup.txt")
        externalFile.writeText(sensitiveData)
        Log.d("KotlinGoat", "Exported to: ${externalFile.absolutePath}")
    }

    private fun getStoredToken(): String {
        return getSharedPreferences("goatlin_prefs", MODE_PRIVATE)
            .getString("auth_token", "") ?: ""
    }

    // ---------------------------------------------------------------
    // VULNERABILITY: SQLite SQL Injection
    // ---------------------------------------------------------------

    /**
     * VULNERABILITY (SQL Injection in Android SQLite):
     * Username parameter concatenated directly into SQLite query string.
     * An attacker who can control the username input can:
     *  - Bypass authentication: username = "' OR '1'='1"
     *  - Extract data: username = "' UNION SELECT password, null FROM accounts--"
     *  - Drop tables: username = "'; DROP TABLE accounts; --"
     *
     * Secure alternative: use rawQuery with ? placeholders or
     *   db.query("accounts", ..., "username = ?", arrayOf(username), ...)
     */
    private fun demonstrateSqlInjection(username: String = "alice' OR '1'='1") {
        val db: SQLiteDatabase = dbHelper.readableDatabase

        // VULNERABILITY: SQL injection via string concatenation
        val cursor = db.rawQuery(
            "SELECT * FROM accounts WHERE username='$username'",
            null
        )

        if (cursor.moveToFirst()) {
            do {
                // VULNERABILITY: Logging sensitive query results
                Log.d("KotlinGoat", "Found user: ${cursor.getString(cursor.getColumnIndex("username"))}" +
                        " password: ${cursor.getString(cursor.getColumnIndex("password"))}")
            } while (cursor.moveToNext())
        }
        cursor.close()
    }

    // ---------------------------------------------------------------
    // VULNERABILITY: Weak Cryptography
    // ---------------------------------------------------------------

    /**
     * VULNERABILITY: AES in ECB mode with hardcoded key.
     * ECB reveals patterns in plaintext.
     * Key is hardcoded and predictable.
     */
    private fun demonstrateWeakCrypto() {
        val data = "sensitive_user_data_123"

        // VULNERABILITY 1: MD5 used for hashing (broken)
        val md5 = MessageDigest.getInstance("MD5")
        val md5Hash = md5.digest(data.toByteArray()).joinToString("") { "%02x".format(it) }
        Log.d("KotlinGoat", "MD5 hash: $md5Hash")

        // VULNERABILITY 2: AES-ECB with hardcoded key
        try {
            val keySpec = SecretKeySpec(AES_KEY.toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")  // ECB mode - insecure
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)
            val encrypted = cipher.doFinal(data.toByteArray())
            val b64 = Base64.getEncoder().encodeToString(encrypted)
            Log.d("KotlinGoat", "ECB encrypted: $b64")
        } catch (e: Exception) {
            Log.e("KotlinGoat", "Crypto error: ${e.message}")
        }

        // VULNERABILITY 3: Base64 used as "encryption"
        val encoded = Base64.getEncoder().encodeToString(data.toByteArray())
        Log.d("KotlinGoat", "Base64 'encrypted': $encoded")  // This is NOT encryption
    }
}
