FROM docker.io/library/golang:1.26.1-alpine@sha256:d337ecb3075f0ec76d81652b3fa52af47c3eba6c8ba9f93b835752df7ce62946 AS builder
WORKDIR /src
COPY xray-core/go.mod xray-core/go.sum ./
RUN go mod download
COPY xray-core/ ./
ARG VERSION=dev
# 固定项目源码构建，运行层无需 Go 编译器或源码。
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X github.com/xtls/xray-core/core.build=msproxy-${VERSION}" -o /out/xray ./main

FROM docker.io/library/nginx:1.29.4-alpine@sha256:a60ab79b8d1cbc6c0860ca9829908c5e7e83ed887034e778fc7adf0b1bfe5e47
RUN apk add --no-cache python3 openssl tini ca-certificates
COPY --from=builder /out/xray /usr/local/bin/xray
COPY xray-core/LICENSE /usr/share/licenses/msproxy/Xray-LICENSE
COPY podman_xray/msproxy.py podman_xray/entrypoint.sh /opt/msproxy/
COPY podman_xray/templates/ /opt/msproxy/templates/
RUN chmod 755 /opt/msproxy/entrypoint.sh
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="msproxy" \
      org.opencontainers.image.description="Nginx TLS + Xray VLESS/XHTTP server" \
      org.opencontainers.image.source="https://github.com/pygojrc/msproxy" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
EXPOSE 8443/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python3 /opt/msproxy/msproxy.py healthcheck
ENTRYPOINT ["/sbin/tini", "--", "/opt/msproxy/entrypoint.sh"]
CMD ["serve"]
