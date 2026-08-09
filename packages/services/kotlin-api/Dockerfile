FROM openjdk:17-jdk-slim

WORKDIR /app

# VULNERABILITY: Running as root (no non-privileged user)
# VULNERABILITY: No health check
# VULNERABILITY: Full JDK instead of JRE (larger attack surface)

COPY build/libs/*.jar app.jar

EXPOSE 8081

# VULNERABILITY: Hardcoded credentials in environment variables baked into image
ENV DB_PASSWORD=Sup3rS3cr3tDBP@ss!
ENV API_KEY=sk-proj-abc123hardcodedkeydonotcommit
ENV JWT_SECRET=super_secret_jwt_key_1234567890_do_not_use_in_prod

# VULNERABILITY: Debug mode enabled, all actuator endpoints exposed
ENV JAVA_OPTS="-Xmx512m -Dspring.profiles.active=dev"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
