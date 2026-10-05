# msproxy

可配置的 Nginx TLS + Xray VLESS/XHTTP 服务端镜像，使用 Podman 构建与部署。

- 镜像：`ghcr.io/pygojrc/msproxy`
- [构建、部署与配置说明](podman_xray/README.md)
- [Xray 源码及上游基线](xray-core/UPSTREAM.md)
- [已有 MSPX 扩展源码](xray-core/proxy/mspx/)

镜像从本仓库 `xray-core/` 编译 Xray；Nginx 终止 TLS，转发至容器内的 VLESS/XHTTP `packet-up` 服务。域名、路径、UUID、加密密钥和证书通过配置文件、环境变量、秘密文件或只读挂载提供。

```bash
podman build --format docker -f podman_xray/Dockerfile -t msproxy:dev .
```

首次初始化生成持久服务端配置及客户端 JSON。后续重启和升级读取已有文件，保留接入凭据。每个实例的真实配置、证书私钥和本地运行资料均由 `.gitignore` 排除。

GitHub Actions 使用 Podman 构建并执行真实 TLS + VLESS/XHTTP 代理测试；版本标签 `v*` 验证通过后发布 GHCR 镜像。首版支持 `linux/amd64`。

本项目使用 MPL-2.0；Xray 保留原许可证。历史部署和私有任务资料保存在本地忽略的 `.ms/` 中。
