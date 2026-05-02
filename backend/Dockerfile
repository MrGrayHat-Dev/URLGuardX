# ============================================================
#  URLGuardX — Multi-stage Dockerfile
#  Stage 1: Build with Maven
#  Stage 2: Run with slim JRE
# ============================================================

# ---------- BUILD STAGE ----------
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /app

# Copy pom first for layer caching — dependencies won't re-download on code-only changes
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# ---------- RUN STAGE ----------
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Non-root user for security
RUN addgroup -S urlguardx && adduser -S urlguardx -G urlguardx
USER urlguardx

# Copy the built JAR from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose the port (matches server.port in application.properties)
EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:10000/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]