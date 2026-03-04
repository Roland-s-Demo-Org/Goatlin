package com.kotlingoat.models

import jakarta.persistence.*
import java.io.Serializable
import java.time.LocalDateTime

// ============================================================
// Domain Models - used across multiple vulnerability demos
// ============================================================

@Entity
@Table(name = "users")
data class User(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    var username: String = "",
    // VULNERABILITY: Passwords stored in plain text (Secrets & Cryptography)
    var password: String = "",
    var email: String = "",
    var role: String = "user",          // "user" or "admin"
    var tenantId: Long = 1,             // Multi-tenant identifier
    var creditBalance: Double = 0.0,
    var isActive: Boolean = true,
    // VULNERABILITY: Sensitive PII stored unencrypted
    var ssn: String = "",
    var creditCardNumber: String = "",
    var cvv: String = ""
)

@Entity
@Table(name = "notes")
data class Note(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    var ownerId: Long = 0,
    var tenantId: Long = 1,
    var title: String = "",
    // VULNERABILITY: HTML content not sanitized (XSS)
    var content: String = "",
    var isPrivate: Boolean = true,
    var createdAt: LocalDateTime = LocalDateTime.now()
)

@Entity
@Table(name = "orders")
data class Order(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    var userId: Long = 0,
    var productId: Long = 0,
    var quantity: Int = 1,
    var price: Double = 0.0,
    var couponCode: String = "",
    var status: String = "pending"
)

@Entity
@Table(name = "products")
data class Product(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    var name: String = "",
    var price: Double = 0.0,
    var stock: Int = 0
)

// DTO classes (request/response)
data class LoginRequest(
    val username: String = "",
    val password: String = ""
)

data class SignupRequest(
    val username: String = "",
    val password: String = "",
    val email: String = "",
    val tenantId: Long = 1
)

data class NoteRequest(
    val title: String = "",
    val content: String = "",
    val isPrivate: Boolean = true
)

data class CouponRequest(
    val couponCode: String = "",
    val productId: Long = 0,
    val quantity: Int = 1
)

data class FetchRequest(
    val url: String = ""
)

data class PingRequest(
    val host: String = ""
)

data class SearchRequest(
    val query: String = ""
)

data class FeedbackRequest(
    val name: String = "",
    // VULNERABILITY: No HTML sanitization - XSS payload stored as-is
    val message: String = ""
)

data class TemplateRequest(
    // VULNERABILITY: User-controlled template fragment for SSTI
    val template: String = ""
)

data class AiChatRequest(
    // VULNERABILITY: User input injected directly into LLM system prompt
    val userMessage: String = "",
    val systemContext: String = ""
)

data class DeserializeRequest(
    // VULNERABILITY: Base64-encoded serialized Java object
    val payload: String = ""
)

data class PasswordResetRequest(
    val token: String = "",
    val newPassword: String = ""
)

data class TransferRequest(
    val fromAccountId: Long = 0,
    val toAccountId: Long = 0,
    val amount: Double = 0.0
)

// VULNERABILITY: Implements Serializable - used for insecure deserialization demo
data class UserSession(
    val userId: Long,
    val username: String,
    val role: String,
    val tenantId: Long
) : Serializable
