package com.kotlingoat.controllers

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

/**
 * VULNERABILITY CATEGORY: Files & Misconfigurations
 *
 * Vulnerabilities demonstrated:
 *  1. Path Traversal / Local File Inclusion (LFI) - reading arbitrary files
 *  2. Unrestricted File Upload - no content-type or extension validation
 *  3. Directory Listing - listing arbitrary filesystem directories
 *  4. Path Control - user-controlled write path enables arbitrary file write
 *  5. Error Leakage - full stack traces and internal paths exposed
 *  6. Zip Slip - malicious archive path traversal during extraction
 */
@RestController
@RequestMapping("/api/files")
class FileController {

    // Base upload directory (but traversal escapes this)
    private val uploadDir = "/tmp/kotlingoat-uploads"

    init {
        File(uploadDir).mkdirs()
    }

    // ---------------------------------------------------------------
    // Path Traversal / LFI
    // ---------------------------------------------------------------

    /**
     * GET /api/files/read?filename=...
     *
     * VULNERABILITY (Path Traversal / LFI):
     * Filename parameter is not sanitized, allowing directory traversal
     * to read any file accessible to the application process.
     *
     * Attack examples:
     *   ?filename=../../../../etc/passwd
     *   ?filename=../../../../etc/shadow
     *   ?filename=../../../../proc/self/environ   (env vars including secrets)
     *   ?filename=../../../../proc/self/cmdline
     *   ?filename=../../application.properties    (app secrets/DB creds)
     *   ?filename=../../../../root/.ssh/id_rsa
     *   ?filename=%2e%2e%2f%2e%2e%2fetc%2fpasswd  (URL-encoded)
     *   ?filename=....//....//etc/passwd           (double-slash bypass)
     */
    @GetMapping("/read")
    fun readFile(@RequestParam filename: String): ResponseEntity<Any> {
        // VULNERABILITY: No canonicalization, no path traversal prevention
        val filePath = "$uploadDir/$filename"

        return try {
            val file = File(filePath)
            // VULNERABILITY: Reads any file, including those outside uploadDir
            val content = file.readText()
            ResponseEntity.ok(mapOf(
                "filename" to filename,
                "path" to filePath,      // VULNERABILITY: Full path disclosed
                "content" to content,
                "size" to file.length()
            ))
        } catch (e: Exception) {
            // VULNERABILITY: Error message reveals internal path structure
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "attemptedPath" to filePath
            ))
        }
    }

    /**
     * GET /api/files/static?path=...
     *
     * VULNERABILITY (LFI via path parameter):
     * Fetches file content using user-supplied path directly.
     * No restriction on absolute paths.
     *
     * Attack:
     *   ?path=/etc/passwd
     *   ?path=/etc/hosts
     *   ?path=/proc/version
     *   ?path=/var/log/auth.log
     */
    @GetMapping("/static")
    fun serveStatic(@RequestParam path: String): ResponseEntity<Any> {
        return try {
            // VULNERABILITY: Absolute path accepted from user input
            val content = Files.readAllBytes(Paths.get(path))
            ResponseEntity.ok()
                .header("Content-Disposition", "inline; filename=${File(path).name}")
                .body(mapOf(
                    "path" to path,
                    "content" to String(content),
                    "size" to content.size
                ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "path" to path
            ))
        }
    }

    // ---------------------------------------------------------------
    // Unrestricted File Upload
    // ---------------------------------------------------------------

    /**
     * POST /api/files/upload
     *
     * VULNERABILITY (Unrestricted File Upload):
     * No validation of file extension, MIME type, or content.
     * Allows uploading:
     *  - Web shells (.jsp, .jspx) - remote code execution
     *  - Malicious scripts (.sh, .py) - execution if server is misconfigured
     *  - Archive bombs (.zip) - denial of service
     *  - SVG files with embedded XSS
     *  - HTML files with JavaScript
     *
     * Attack (JSP Web Shell upload):
     *   Upload file named: shell.jsp
     *   Content: <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
     *   Then: GET /uploads/shell.jsp?cmd=id
     *
     * VULNERABILITY: Original filename used directly (path traversal possible)
     *   Upload file named: ../../shell.jsp -> writes outside uploadDir
     */
    @PostMapping("/upload")
    fun uploadFile(
        @RequestParam("file") file: MultipartFile,
        @RequestParam(required = false) destination: String?
    ): ResponseEntity<Any> {
        // VULNERABILITY: No content-type validation
        // VULNERABILITY: No file extension allowlist/blocklist
        // VULNERABILITY: Original filename used directly without sanitization
        val filename = file.originalFilename ?: "unknown"

        // VULNERABILITY: Destination parameter allows writing to arbitrary paths
        val targetDir = if (destination != null) {
            // VULNERABILITY: Path traversal via destination parameter
            File(destination).also { it.mkdirs() }
        } else {
            File(uploadDir)
        }

        // VULNERABILITY: User-controlled filename written to filesystem (path traversal + web shell)
        val targetFile = File(targetDir, filename)
        file.transferTo(targetFile)

        return ResponseEntity.ok(mapOf(
            "message" to "File uploaded successfully",
            "filename" to filename,
            // VULNERABILITY: Full server-side path disclosed
            "savedTo" to targetFile.absolutePath,
            "size" to file.size,
            // VULNERABILITY: Content-Type not validated - could be anything
            "contentType" to file.contentType
        ))
    }

    /**
     * POST /api/files/upload-avatar
     *
     * VULNERABILITY (File Upload - Content Type Spoofing):
     * Only checks Content-Type header (attacker-controlled), not actual file content.
     * An attacker can upload a JSP shell with Content-Type: image/jpeg.
     *
     * Attack:
     *   Upload shell.jsp with header Content-Type: image/jpeg
     *   -> Passes the "validation", executes as JSP
     */
    @PostMapping("/upload-avatar")
    fun uploadAvatar(@RequestParam("avatar") file: MultipartFile): ResponseEntity<Any> {
        val contentType = file.contentType ?: ""

        // VULNERABILITY: Only checks Content-Type header, not magic bytes or extension
        // Attacker can set any Content-Type they want
        if (!contentType.startsWith("image/")) {
            return ResponseEntity.status(400).body(mapOf("error" to "Only images allowed"))
        }

        // VULNERABILITY: Extension from original filename, not content type
        val extension = file.originalFilename?.substringAfterLast(".") ?: "bin"
        val savedName = "avatar_${System.currentTimeMillis()}.$extension"
        val targetFile = File(uploadDir, savedName)
        file.transferTo(targetFile)

        return ResponseEntity.ok(mapOf(
            "message" to "Avatar uploaded",
            "path" to targetFile.absolutePath
        ))
    }

    // ---------------------------------------------------------------
    // Directory Listing
    // ---------------------------------------------------------------

    /**
     * GET /api/files/list?dir=...
     *
     * VULNERABILITY (Directory Listing / Path Control):
     * Lists any directory on the filesystem accessible to the process.
     *
     * Attack:
     *   ?dir=/etc
     *   ?dir=/tmp
     *   ?dir=/root
     *   ?dir=/var/log
     *   ?dir=../../..
     */
    @GetMapping("/list")
    fun listDirectory(@RequestParam dir: String): ResponseEntity<Any> {
        return try {
            // VULNERABILITY: No restriction on which directories can be listed
            val directory = File(dir)
            val files = directory.listFiles()?.map { f ->
                mapOf(
                    "name" to f.name,
                    "path" to f.absolutePath,    // Full path disclosed
                    "isDirectory" to f.isDirectory,
                    "size" to f.length(),
                    "readable" to f.canRead(),
                    "writable" to f.canWrite(),
                    "executable" to f.canExecute(),
                    "lastModified" to f.lastModified()
                )
            } ?: emptyList<Map<String, Any>>()

            ResponseEntity.ok(mapOf(
                "directory" to dir,
                "absolutePath" to directory.absolutePath,
                "count" to files.size,
                "files" to files
            ))
        } catch (e: Exception) {
            ResponseEntity.status(500).body(mapOf(
                "error" to e.message,
                "directory" to dir
            ))
        }
    }

    // ---------------------------------------------------------------
    // Error Leakage
    // ---------------------------------------------------------------

    /**
     * GET /api/files/process?filename=...
     *
     * VULNERABILITY (Error Leakage):
     * Full stack traces exposed in error responses, revealing:
     *  - Internal package/class names
     *  - File system paths
     *  - Framework versions
     *  - Database connection details (in some cases)
     *
     * Note: application.properties sets server.error.include-stacktrace=always
     * Any unhandled exception will produce a full stack trace response.
     *
     * Attack: Supply invalid/non-existent filename to trigger error response
     *   ?filename=nonexistent_file_to_trigger_error
     */
    @GetMapping("/process")
    fun processFile(@RequestParam filename: String): ResponseEntity<Any> {
        // VULNERABILITY: Exception thrown with internal details, not caught/sanitized
        val file = File("$uploadDir/$filename")

        // This will throw an exception with internal path info if file doesn't exist
        val content = file.readText()   // throws FileNotFoundException with full path

        return ResponseEntity.ok(mapOf("content" to content))
    }
}
