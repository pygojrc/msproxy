# msproxy 容器

单镜像包含 Nginx、项目源码编译的 Xray、Python 标准库配置工具和 tini。Nginx 提供 TLS，Xray 只监听容器内 loopback，传输采用 VLESS Encryption + XHTTP `packet-up`。

## 构建

在项目根目录执行：

```bash
podman build --format docker -f podman_xray/Dockerfile -t msproxy:dev .
```

首版为 linux/amd64，Go 1.26.1 和 Nginx 1.29.4 基础镜像已固定 digest。运行层不包含 Go、项目源码、域名或接入凭据。若构建环境的 HTTP_PROXY 指向宿主机 loopback，可在本机增加 `--network host`，使构建步骤能够访问该代理；这只影响构建网络。

## 初始化与启动

准备一个持久配置目录和一个包含 `cert.pem`、`key.pem` 的证书目录。证书必须覆盖实际域名。Cloudflare 代理场景可使用覆盖该域名的 Origin CA 证书，Cloudflare 到源站使用 Full (strict)。客户端验证 Cloudflare 边缘证书。

以下示例需替换域名和宿主机路径：

```bash
podman run --rm \
  -v /etc/msproxy/config:/config \
  ghcr.io/pygojrc/msproxy:v0.1.0 \
  init -d proxy.example.com

podman run -d --name msproxy \
  -p 443:8443 \
  -v /etc/msproxy/config:/config:ro \
  -v /etc/msproxy/certs:/certs:ro \
  -e MSPROXY_CONFIG_FILE=/config/server.json \
  ghcr.io/pygojrc/msproxy:v0.1.0
```

初始化生成 `server.json` 和 `client.json`，权限 0600，包含独立 UUID、ML-KEM 认证密钥、随机 XHTTP 路径。已有任一文件时拒绝覆盖；重启不会重新生成密钥。配置目录应限制为部署用户可访问，证书私钥权限0600。SELinux 宿主机按实际挂载共享方式添加 `:Z` 或 `:z`。

发布宿主机 443 时使用有权限绑定该端口的 Podman/systemd 服务；rootless 默认可先发布 8443 或其他高端口。现有 Nginx 已占用443时，先使用其他端口验证，再单独迁移路由。

`init` 的常用选项：`-d/--domain`、`-o/--output`、`-c/--tls-cert`、`-k/--tls-key`、`-p/--public-port`、`-s/--socks-port`、`-x/--xhttp-path`、`-a/--tls-ca`。public-port 是客户端连接的对外端口，默认443；socks-port 是客户端本地端口，默认1080。tls-ca 是客户端额外信任 CA 的绝对路径，只在自有 CA 等场景使用。

## 配置来源

配置优先级：默认值 → `MSPROXY_CONFIG_FILE` 指定的 JSON → 显式环境变量。未知字段会报错。

| JSON 字段 | 环境变量 | 默认值/说明 |
|---|---|---|
| domain | MSPROXY_DOMAIN | 必填，域名或 IPv4 |
| xhttp_path | MSPROXY_XHTTP_PATH | 必填，独立路径 |
| uuid | MSPROXY_UUID | 必填，VLESS 用户 UUID |
| vless_decryption | MSPROXY_VLESS_DECRYPTION | 必填，完整 VLESS Encryption 服务端参数 |
| tls_cert_file | MSPROXY_TLS_CERT_FILE | /certs/cert.pem |
| tls_key_file | MSPROXY_TLS_KEY_FILE | /certs/key.pem |
| https_port | MSPROXY_HTTPS_PORT | 8443，容器 TLS 端口 |
| xray_port | MSPROXY_XRAY_PORT | 10086，容器 loopback 端口 |
| public_port | MSPROXY_PUBLIC_PORT | 443，导出客户端的服务端端口 |
| socks_port | MSPROXY_SOCKS_PORT | 1080，导出客户端的本地端口 |
| log_level | MSPROXY_LOG_LEVEL | warning |
| tls_ca_file | MSPROXY_TLS_CA_FILE | 可选，客户端额外信任 CA 文件路径 |

UUID 和 decryption 可以通过 `MSPROXY_UUID_FILE`、`MSPROXY_VLESS_DECRYPTION_FILE` 读取纯文本文件。同一字段的普通变量与 `_FILE` 同时出现时拒绝启动；环境变量及 secret 文件必须由部署者提供。证书变量指定容器内文件路径，证书通过只读挂载或 Podman secret 提供。

```bash
podman secret create msproxy-decryption /etc/msproxy/decryption.txt
podman run -d --name msproxy \
  -p 443:8443 \
  -v /etc/msproxy/certs:/certs:ro \
  --secret msproxy-decryption \
  -e MSPROXY_DOMAIN=proxy.example.com \
  -e MSPROXY_XHTTP_PATH=/your-private-path \
  -e MSPROXY_UUID=YOUR_UUID \
  -e MSPROXY_VLESS_DECRYPTION_FILE=/run/secrets/msproxy-decryption \
  ghcr.io/pygojrc/msproxy:v0.1.0
```

镜像默认以容器 root 启动，Nginx worker 使用 nginx 用户；支持 rootless Podman。需要确保运行身份能读取挂载文件。启动会检查证书有效期、域名及密钥匹配，验证 Nginx/Xray 配置；错误日志不回显 VLESS 密钥。

## 导出客户端及检查

从既有配置重新导出客户端至新的文件：

```bash
podman run --rm \
  -v /etc/msproxy/config:/config \
  -e MSPROXY_CONFIG_FILE=/config/server.json \
  ghcr.io/pygojrc/msproxy:v0.1.0 \
  client -o /config/client-export.json
```

`client.json` 使用 VLESS Encryption、XHTTP packet-up、TLS 校验和 SOCKS5 127.0.0.1:1080。客户端公钥由服务端私钥推导，服务端私钥不写入客户端。域名、对外端口或路径变更后应重新导出。

运行 `check` 验证配置，运行 `healthcheck` 检查两个进程、Xray TCP 和 Nginx `/healthz`。健康检查只判断容器内服务存活，独立端到端测试验证代理业务和 TLS 信任。任一子进程退出时整个容器以非零状态结束；SIGTERM 会停止两个进程。

## systemd 部署

参考 `deploy/msproxy.container`，替换宿主挂载路径后放入 `/etc/containers/systemd/`，执行 `systemctl daemon-reload` 和 `systemctl start msproxy.service`。Quadlet 的 `[Install]` 设置随系统启动拉起服务。镜像升级使用固定版本或 digest，持久配置保持不变。证书更新后重启容器加载新文件。

## 验证与发布

```bash
uv run python -m unittest discover -s podman_xray/tests -p 'test_*.py' -v
uv run podman_xray/tests/integration.py -i localhost/msproxy:dev -o .ms/tasks/container-test/temp/running_test
```

集成测试使用临时自签测试证书作为显式信任锚，保持客户端 TLS 校验开启；经真实 VLESS/XHTTP 传输本地目标 HTTP 数据，检查重复初始化保护、容器重建凭据保留及子进程退出联动。测试产生的凭据保存在被忽略的运行目录，测试容器和客户端结束后停止。

普通 main 提交/PR 执行验证，版本标签 `v*` 通过验证后发布 `ghcr.io/pygojrc/msproxy:<版本>` 及 `sha-<提交前12位>`。可手动触发仅验证。GHCR 包的公开可见性需在包设置中管理。
