package com.kotlingoat.controllers

import com.kotlingoat.models.*
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.concurrent.ConcurrentHashMap

/**
 * VULNERABILITY CATEGORY: Business Logic & Validation
 *
 * Vulnerabilities demonstrated:
 *  1. Negative quantity/amount allowed (purchasing at negative price = free credit)
 *  2. Race condition on limited-use coupon (apply same coupon concurrently multiple times)
 *  3. Integer overflow / floating point manipulation
 *  4. Price manipulation via client-supplied price
 *  5. Workflow bypass (skip payment step)
 *  6. Mass coupon brute force (short coupon codes, no rate limit)
 *  7. Insufficient input validation (empty/null fields accepted)
 *  8. Negative withdrawal resulting in credit to account
 *  9. Discount stacking (apply multiple conflicting promotions)
 * 10. Insecure Direct Object Reference in order status manipulation
 */
@RestController
@RequestMapping("/api/shop")
class BusinessLogicController {

    @PersistenceContext
    lateinit var em: EntityManager

    // Simulated coupon store: code -> discount percentage
    private val validCoupons = ConcurrentHashMap<String, Int>().apply {
        put("SAVE10", 10)
        put("SAVE50", 50)
        put("FREE100", 100)
        // VULNERABILITY: Short, predictable coupon codes easy to brute force
        put("A1", 25)
        put("B2", 30)
    }

    // Track coupon usage - but with race condition vulnerability
    private val couponUsageCount = ConcurrentHashMap<String, Int>()

    // ---------------------------------------------------------------
    // Negative Quantity / Price Manipulation
    // ---------------------------------------------------------------

    /**
     * POST /api/shop/purchase
     *
     * VULNERABILITY 1 (Negative Quantity): A negative quantity results in a
     * negative total price, which causes the system to credit the user's account.
     * e.g., quantity=-10, price=100 -> total=-1000 -> balance increases by 1000
     *
     * VULNERABILITY 2 (Client-Supplied Price): The price is taken from the
     * request body instead of from the database. An attacker can set price=0.01.
     *
     * VULNERABILITY 3 (No Stock Validation): Stock is not checked, allowing
     * unlimited purchases beyond available inventory.
     *
     * Attack 1 (get free credit):
     *   {"productId":1, "quantity":-100, "price":50.0}
     *   -> balance increases by 5000
     *
     * Attack 2 (free goods):
     *   {"productId":1, "quantity":1, "price":0.001}
     *   -> purchase for fraction of a cent
     */
    @PostMapping("/purchase")
    fun purchaseItem(
        @RequestBody order: Map<String, Any>,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val productId = (order["productId"] as? Number)?.toLong() ?: 1L
        // VULNERABILITY: Price taken from request body, not from database
        val clientPrice = (order["price"] as? Number)?.toDouble() ?: 0.0
        // VULNERABILITY: Negative quantity not rejected
        val quantity = (order["quantity"] as? Number)?.toInt() ?: 1

        val product = em.find(Product::class.java, productId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Product not found"))

        // VULNERABILITY: Using client-supplied price instead of product.price
        val totalCost = clientPrice * quantity

        // VULNERABILITY: No minimum validation on quantity or price
        // Negative totalCost means system credits the user

        return ResponseEntity.ok(mapOf(
            "productName" to product.name,
            "dbPrice" to product.price,
            "chargedPrice" to clientPrice,    // Using attacker-controlled price
            "quantity" to quantity,
            "totalCharged" to totalCost,       // Can be negative
            "message" to if (totalCost < 0) "Congratulations! Credit applied!" else "Purchase complete"
        ))
    }

    // ---------------------------------------------------------------
    // Coupon Race Condition
    // ---------------------------------------------------------------

    /**
     * POST /api/shop/apply-coupon
     *
     * VULNERABILITY (Race Condition - TOCTOU):
     * Coupon validation (check) and usage-count increment (update) are not atomic.
     * A concurrent attacker can send many requests simultaneously, all passing the
     * "is usage count < max?" check before any of them increment the counter.
     *
     * Attack:
     *   Send 50 simultaneous POST requests with coupon code "SAVE50"
     *   where max uses is 1. All 50 requests will see count=0 and apply the discount.
     *
     * VULNERABILITY (Discount Stacking):
     *   Apply coupon first: get 50% off
     *   Then apply coupon again in next request (no single-use enforcement)
     */
    @PostMapping("/apply-coupon")
    fun applyCoupon(
        @RequestBody request: CouponRequest,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val code = request.couponCode.uppercase()

        val discount = validCoupons[code]
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Invalid coupon code"))

        // VULNERABILITY: Check-then-act race condition (TOCTOU)
        // Between the check and the increment, another thread can pass the same check
        val currentUsage = couponUsageCount.getOrDefault(code, 0)
        val maxUses = 1

        if (currentUsage >= maxUses) {
            return ResponseEntity.status(400).body(mapOf("error" to "Coupon already used"))
        }

        // VULNERABILITY: Non-atomic increment - race window here
        Thread.sleep(10)  // Artificial delay to widen race window for demo
        couponUsageCount[code] = currentUsage + 1

        val product = em.find(Product::class.java, request.productId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Product not found"))

        val discountedPrice = product.price * (1 - discount / 100.0)

        return ResponseEntity.ok(mapOf(
            "originalPrice" to product.price,
            "discountPercent" to discount,
            "discountedPrice" to discountedPrice,
            "couponApplied" to code,
            "usageCount" to couponUsageCount[code]
        ))
    }

    /**
     * GET /api/shop/coupon/check?code=...
     *
     * VULNERABILITY (Coupon Brute Force):
     * No rate limiting on coupon code validation.
     * Short, predictable codes (A1, B2, etc.) can be enumerated automatically.
     *
     * Attack:
     *   for code in [A0..Z9]:
     *     GET /api/shop/coupon/check?code=<code>
     *   -> Discovers all valid codes quickly
     */
    @GetMapping("/coupon/check")
    fun checkCoupon(@RequestParam code: String): ResponseEntity<Any> {
        // VULNERABILITY: No rate limiting, reveals which codes are valid
        val discount = validCoupons[code.uppercase()]
        return if (discount != null) {
            ResponseEntity.ok(mapOf("valid" to true, "discount" to discount))
        } else {
            ResponseEntity.status(404).body(mapOf("valid" to false))
        }
    }

    // ---------------------------------------------------------------
    // Workflow Bypass / Step Skipping
    // ---------------------------------------------------------------

    /**
     * POST /api/shop/complete-order
     *
     * VULNERABILITY (Workflow Bypass):
     * The order completion endpoint can be called directly without going through
     * the payment step. No server-side enforcement of the business flow:
     * cart -> payment -> order completion.
     *
     * Attack:
     *   Skip payment entirely:
     *   POST /api/shop/complete-order {"orderId": 123}
     *   -> Order marked as "paid" without actual payment
     */
    @PostMapping("/complete-order")
    fun completeOrder(
        @RequestBody body: Map<String, Any>,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val orderId = (body["orderId"] as? Number)?.toLong() ?: 0L

        val order = em.find(Order::class.java, orderId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Order not found"))

        // VULNERABILITY: No check that payment was actually processed
        // No check of order.status == "payment_confirmed" before completion
        order.status = "completed"
        em.merge(order)

        return ResponseEntity.ok(mapOf(
            "message" to "Order completed (payment step skipped!)",
            "orderId" to orderId,
            "status" to "completed"
        ))
    }

    // ---------------------------------------------------------------
    // Integer / Floating Point Manipulation
    // ---------------------------------------------------------------

    /**
     * POST /api/shop/transfer-points
     *
     * VULNERABILITY (Integer Overflow):
     * No upper bound validation on points transfer.
     * Transferring Integer.MAX_VALUE points can cause overflow in calculations.
     *
     * VULNERABILITY (Negative Transfer = Theft):
     * Negative amount transfers points FROM the recipient TO the sender.
     *
     * Attack:
     *   {"fromUserId":1, "toUserId":2, "amount":-1000}
     *   -> Takes 1000 points FROM user 2 and gives to user 1
     */
    @PostMapping("/transfer-points")
    fun transferPoints(
        @RequestBody body: Map<String, Any>,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val fromUserId = (body["fromUserId"] as? Number)?.toLong() ?: 0L
        val toUserId = (body["toUserId"] as? Number)?.toLong() ?: 0L
        // VULNERABILITY: Negative amount not validated
        val amount = (body["amount"] as? Number)?.toDouble() ?: 0.0

        val fromUser = em.find(User::class.java, fromUserId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Sender not found"))
        val toUser = em.find(User::class.java, toUserId)
            ?: return ResponseEntity.status(404).body(mapOf("error" to "Recipient not found"))

        // VULNERABILITY: No BOLA check (any user can transfer from any account)
        // VULNERABILITY: Negative amount reverses transfer direction
        fromUser.creditBalance -= amount
        toUser.creditBalance += amount

        em.merge(fromUser)
        em.merge(toUser)

        return ResponseEntity.ok(mapOf(
            "transferred" to amount,
            "senderBalance" to fromUser.creditBalance,
            "recipientBalance" to toUser.creditBalance
        ))
    }

    // ---------------------------------------------------------------
    // Insufficient Input Validation
    // ---------------------------------------------------------------

    /**
     * POST /api/shop/create-listing
     *
     * VULNERABILITY (Insufficient Validation - Negative Price):
     * Product can be listed with a negative price. When purchased, this
     * creates a "credit" transaction, effectively giving the buyer money.
     *
     * Attack:
     *   {"name":"Attack Product","price":-9999.99,"stock":1}
     *   -> Create product with negative price
     *   Then purchase it -> buyer receives credit
     */
    @PostMapping("/create-listing")
    fun createListing(
        @RequestBody body: Map<String, Any>,
        @RequestHeader(value = "Authorization", required = false) authHeader: String?
    ): ResponseEntity<Any> {
        val name = body["name"]?.toString() ?: ""
        // VULNERABILITY: No lower-bound validation on price
        val price = (body["price"] as? Number)?.toDouble() ?: 0.0
        // VULNERABILITY: No upper-bound validation on stock (can create unlimited stock)
        val stock = (body["stock"] as? Number)?.toInt() ?: 0

        val product = Product(name = name, price = price, stock = stock)
        em.persist(product)

        return ResponseEntity.ok(mapOf(
            "message" to "Listing created",
            "product" to mapOf(
                "id" to product.id,
                "name" to product.name,
                "price" to product.price,
                "stock" to product.stock
            )
        ))
    }
}
