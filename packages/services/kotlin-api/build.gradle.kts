import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "3.1.5"
    id("io.spring.dependency-management") version "1.1.3"
    kotlin("jvm") version "1.8.22"
    kotlin("plugin.spring") version "1.8.22"
    kotlin("plugin.jpa") version "1.8.22"
}

group = "com.kotlingoat"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    // Intentionally vulnerable: old versions kept for exploit demos
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    // H2 in-memory DB for easy SQLi demos
    implementation("com.h2database:h2")
    // JWT library - intentionally using older version with known issues
    implementation("io.jsonwebtoken:jjwt:0.9.1")
    // XML support (for XXE demos)
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    // Commons-lang for command execution helpers
    implementation("org.apache.commons:commons-lang3:3.12.0")
    // OkHttp for SSRF demos
    implementation("com.squareup.okhttp3:okhttp:4.11.0")
    // Thymeleaf extras (SSTI potential)
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xjsr305=strict"
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
