# AegisX data plane (PEP): Netty proxy, built as a shaded jar.
#
# Two stages: Maven + JDK to build, slim JRE to run. The runtime image has no
# Maven, no source, and no JDK -- just the jar.

# --- Stage 1: build ---------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /build

COPY pom.xml .
COPY src/ ./src/

# -DskipTests: tests run in CI; the image build just needs the jar.
RUN mvn -B package -DskipTests

# --- Stage 2: run -----------------------------------------------------------
FROM eclipse-temurin:17-jre

WORKDIR /app

# Jar name comes from <finalName>aegisx-ztna-proxy</finalName> in pom.xml.
COPY --from=build /build/target/aegisx-ztna-proxy.jar ./aegisx-ztna-proxy.jar

# 9000 is the PEP listen port (AEGISX_PEP_PORT default).
EXPOSE 9000

# --enable-native-access=ALL-UNNAMED matches the demo scripts (Netty needs it
# on newer JDKs for direct buffer access).
CMD ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "aegisx-ztna-proxy.jar"]
