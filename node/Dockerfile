# Build context is the repository root:  docker build -f node/Dockerfile .
FROM alpine:3.20 AS xray
ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH
RUN apk add --no-cache curl unzip \
 && case "${TARGETARCH:-amd64}" in arm64) A=arm64-v8a ;; *) A=64 ;; esac \
 && U="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${A}.zip" \
 && curl -fsSL -o /tmp/x.zip "$U" && curl -fsSL -o /tmp/x.dgst "$U.dgst" \
 && WANT="$(sed -n 's/^SHA2-256= *//p' /tmp/x.dgst)" \
 && [ -n "$WANT" ] && echo "$WANT  /tmp/x.zip" | sha256sum -c - \
 && unzip -q /tmp/x.zip xray -d /out && chmod +x /out/xray

FROM node:22-alpine
RUN apk add --no-cache openssl tini
COPY --from=xray /out/xray /usr/local/bin/xray
WORKDIR /app
COPY node/ /app/
COPY web/ /app/web/
ENV DATA_DIR=/data WEB_DIR=/app/web XRAY_BIN=/usr/local/bin/xray NODE_ENV=production
VOLUME ["/data"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "/app/server.js"]
