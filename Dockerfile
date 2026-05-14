# Stage 1: Build the Go binary
FROM golang:1.24-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/reversio .

# Stage 2: Runtime with Ghidra + JDK
FROM eclipse-temurin:21-jre-jammy

ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
ARG GHIDRA_SHA256=a51328fade43deb39e6a8741055bd2e0e73bd5a66e7e5da4da610b9cf5e79e71

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_PROJECT_PATH=/ghidra-projects
ENV GHIDRA_SCRIPTS_PATH=/app/resources/ghidra_scripts
ENV HEADLESS_GHIDRA_PATH=/opt/ghidra/support

RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip \
        wget \
        fontconfig \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
RUN wget -q -O /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} \
    && rm /tmp/ghidra.zip \
    && chmod +x ${GHIDRA_HOME}/support/analyzeHeadless

# Create required directories
RUN mkdir -p ${GHIDRA_PROJECT_PATH} /app/data

WORKDIR /app

# Copy built binary and resources
COPY --from=builder /out/reversio .
COPY resources/ ./resources/

# Create .env for container use
RUN printf "HEADLESS_GHIDRA_PATH=%s\nGHIDRA_PROJECT_PATH=%s\nGHIDRA_SCRIPTS_PATH=%s\n" \
    "${HEADLESS_GHIDRA_PATH}" "${GHIDRA_PROJECT_PATH}" "${GHIDRA_SCRIPTS_PATH}" > .env

ENTRYPOINT ["./reversio"]
