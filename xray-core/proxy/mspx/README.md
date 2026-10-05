# MSPX

通用 TCP 代理协议，配置入口为 `MSPX` 或 `mspx`，传输和路由使用 Xray 自身配置。首版提供入站、出站、PSK/HMAC 认证、HKDF/AES-GCM 加密、长度分帧、双向窗口和有序半关闭。不提供 UDP/Mux。

- `config.proto` / `config.go`：protobuf、账户与密钥校验。
- `wire.go`：字节流分帧、握手、认证加密和消息校验。
- `relay.go`：Xray Link 与协议连接之间的背压、超时和收尾。
- `mspx.go`：原生 Dispatcher/Dialer 接入。

JSON 入站 `settings.clients` 为 `{psk,email?,level?}` 数组。出站 `settings` 为 `{address,port,psk,email?,level?}`。PSK 必须是32字节的标准 base64 编码。目标支持域名、IPv4、IPv6与合法 TCP 端口，不含目标白名单。

协议记录为两字节大端长度加消息体，不依赖 WS 消息边界。原生 RESULT.ok 只承诺请求接受并开始路由。配置与协议详细说明位于自有项目的 `.ms/tasks/2026-10-03_mspx-xray/docs/`。

回归：`go test -race ./proxy/mspx ./infra/conf ./proxy/freedom`。核心测试覆盖拆分分帧、认证篡改、重放、窗口耗尽、双向背压、满队列 EOF、延迟最终 WINDOW 与尾部完整性。
