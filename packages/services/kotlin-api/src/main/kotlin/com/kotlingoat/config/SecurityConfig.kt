package com.kotlingoat.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

/**
 * VULNERABILITY CATEGORY: Hardening - CORS Misconfiguration + Missing Security Headers
 *
 * This security configuration is intentionally permissive and missing
 * critical defensive controls. It demonstrates:
 *  1. Wildcard CORS allowing any origin with credentials
 *  2. CSRF protection disabled globally
 *  3. All endpoints publicly accessible (no authentication enforcement)
 *  4. No Content-Security-Policy header
 *  5. No X-Frame-Options (clickjacking risk)
 *  6. No HSTS
 *  7. No X-Content-Type-Options
 *  8. H2 console left open
 *
 * DO NOT use this configuration in production.
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            // VULNERABILITY: CSRF completely disabled
            .csrf { it.disable() }

            // VULNERABILITY: All requests permitted without authentication
            .authorizeHttpRequests { auth ->
                auth.anyRequest().permitAll()
            }

            // VULNERABILITY: Permissive CORS applied globally
            .cors { it.configurationSource(corsConfigurationSource()) }

            // VULNERABILITY: Framebreaking disabled - clickjacking risk
            .headers { headers ->
                headers.frameOptions { it.disable() }
                // VULNERABILITY: No Content-Security-Policy set
                // VULNERABILITY: No HSTS configured
                // VULNERABILITY: No X-Content-Type-Options
                // VULNERABILITY: No Referrer-Policy
                // VULNERABILITY: No Permissions-Policy
            }

        return http.build()
    }

    /**
     * VULNERABILITY: CORS configured to allow ANY origin with credentials.
     * This means any website can make authenticated cross-origin requests.
     *
     * Secure alternative would restrict allowedOrigins to known domains
     * and NOT combine allowCredentials=true with wildcard origins.
     */
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val config = CorsConfiguration()
        // VULNERABILITY: Wildcard origin with credentials - complete CORS bypass
        config.allowedOriginPatterns = listOf("*")
        config.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
        config.allowedHeaders = listOf("*")
        config.exposedHeaders = listOf("Authorization", "X-Auth-Token")
        // VULNERABILITY: Credentials allowed with wildcard origin
        config.allowCredentials = true
        config.maxAge = 3600L

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }
}
