# syntax=docker/dockerfile:1
# ---- build: compile and run the unit tests
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B package

# ---- runtime: JRE only, non-root user
FROM eclipse-temurin:21-jre
RUN groupadd --system app && useradd --system --gid app --home /app app \
    && mkdir -p /app /var/lib/mtls/crl && chown -R app:app /app /var/lib/mtls
WORKDIR /app
COPY --from=build /src/target/mtls-auth.jar /app/app.jar
USER app
EXPOSE 8080
# The CRL bundle is written before the web server starts, so "port open" means "ready".
HEALTHCHECK --interval=5s --timeout=3s --start-period=60s --retries=20 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
