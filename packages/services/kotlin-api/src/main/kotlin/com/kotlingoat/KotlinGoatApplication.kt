package com.kotlingoat

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

/**
 * KotlinGoat - Deliberately Vulnerable Application
 *
 * PURPOSE: Security education and penetration testing practice.
 * This application intentionally contains numerous vulnerabilities
 * across all OWASP Top 10 categories and beyond.
 *
 * WARNING: DO NOT deploy this in a production environment.
 * DO NOT use any patterns here in real applications.
 *
 * Vulnerability Categories Demonstrated:
 *  - Broken Access Control (BOLA/IDOR)
 *  - SQL & NoSQL Injection
 *  - Command Injection / RCE
 *  - Server-Side Request Forgery (SSRF)
 *  - Authentication & Session Management Flaws
 *  - Cross-Site Scripting (XSS) & CSRF
 *  - Insecure Deserialization
 *  - Server-Side Template Injection (SSTI)
 *  - File Upload & Path Traversal (LFI)
 *  - Hardcoded Secrets & Weak Cryptography
 *  - Misconfigured CORS & Missing Security Headers
 *  - LLM Prompt Injection
 *  - Business Logic Flaws
 */
@SpringBootApplication
class KotlinGoatApplication

fun main(args: Array<String>) {
    runApplication<KotlinGoatApplication>(*args)
}
