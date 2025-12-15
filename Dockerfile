# Multi-stage build for Toxic SOAP

# Stage 1: Build
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /app

# Install Maven
RUN apk add --no-cache maven

# Copy pom.xml and source code
COPY pom.xml .
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Install useful tools for vulnerability testing
RUN apk add --no-cache curl

# Copy the built JAR
COPY --from=builder /app/target/*.jar app.jar

# Create non-root user (though for vuln testing, we'll run as root)
# RUN addgroup -S toxicsoap && adduser -S toxicsoap -G toxicsoap
# USER toxicsoap

# Expose port
EXPOSE 4040

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:4040/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
