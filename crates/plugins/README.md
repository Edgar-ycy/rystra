# Rystra Plugins 目录结构

本目录包含 Rystra 项目的所有插件模块，采用插件化架构设计，便于扩展和维护。

## 目录结构

```
plugins/
├── proxy/                          # 代理插件组
│   ├── rystra-proxy-tcp/           # ✅ MVP
│   ├── rystra-proxy-http/          # 规划
│   └── rystra-proxy-udp/           # 规划
├── transport/                      # 传输层插件组
│   ├── rystra-transport-tcp/       # ✅ MVP
│   ├── rystra-transport-tls/       # ✅ 已完成
│   └── rystra-transport-quic/      # 规划
├── auth/                           # 认证插件组
│   ├── rystra-auth-token/          # ✅ MVP
│   └── rystra-auth-mtls/           # 规划
├── hook/                           # 钩子插件组
│   └── rystra-hook-rate/           # 规划
└── mux/                            # 多路复用插件组
    └── rystra-mux-smux/            # 规划
```

---

## proxy/ - 代理插件组

代理插件负责处理不同协议的代理逻辑，将客户端请求转发到目标服务。

### rystra-proxy-tcp/  `✅ MVP`

**功能**: TCP 代理插件

**说明**: 处理 TCP 层级的代理转发，实现原始 TCP 流量的双向透传。

**当前状态**: 占位模块，核心逻辑已在 `rystra-server` 和 `rystra-client` 中实现，后续计划抽象到此插件。

**文件结构**:
- `src/lib.rs` - 插件入口和占位声明
- `Cargo.toml` - 依赖配置

---

### rystra-proxy-http/  `规划`

**功能**: HTTP 代理插件

**说明**: 处理 HTTP/HTTPS 协议的代理转发，支持 HTTP 请求解析和路由。

**当前状态**: 占位模块，核心逻辑已在 `rystra-server` 和 `rystra-client` 中实现，后续计划抽象到此插件。

**文件结构**:
- `src/lib.rs` - 插件入口和占位声明
- `Cargo.toml` - 依赖配置

---

### rystra-proxy-udp/  `规划`

**功能**: UDP 代理插件

**说明**: 处理 UDP 协议的代理转发，支持无连接的数据报传输。

**规划特性**:
- UDP 数据报转发
- 会话管理
- 超时处理

---

## transport/ - 传输层插件组

传输层插件负责底层网络连接的建立和数据传输，实现 `TransportPlugin` trait。

### rystra-transport-tcp/  `✅ MVP`

**功能**: TCP 传输插件

**说明**: 提供基础的 TCP 连接能力，是最基本的传输层实现。

**核心组件**:
- `TcpTransportPlugin` - 插件主体，实现 `TransportPlugin` trait
- `TcpTransportListener` - TCP 监听器，实现 `TransportListener` trait
- `TcpTransportStream` - TCP 流，实现 `TransportStream` trait

**主要方法**:
- `listen(addr)` - 在指定地址监听连接
- `connect(addr)` - 连接到指定地址

**文件结构**:
- `src/lib.rs` - 完整的 TCP 传输实现
- `Cargo.toml` - 依赖配置

---

### rystra-transport-tls/  `✅ 已完成`

**功能**: TLS 加密传输插件

**说明**: 在 TCP 基础上提供 TLS 加密能力，支持安全的数据传输。

**核心组件**:
- `TlsTransportPlugin` - 插件主体，支持服务端和客户端模式
- `TlsTransportListener` - TLS 监听器
- `TlsServerStream` / `TlsClientStream` - 服务端/客户端 TLS 流

**初始化方式**:
- `new_server(cert_path, key_path)` - 创建服务端插件，需提供证书和私钥
- `new_client(ca_path)` - 创建客户端插件，需提供 CA 证书
- `new_client_insecure()` - 创建不验证证书的客户端（仅用于测试）

**辅助功能**:
- `load_certs(path)` - 加载 PEM 格式证书
- `load_key(path)` - 加载 PEM 格式私钥
- `NoCertificateVerification` - 跳过证书验证（危险，仅用于测试）

**文件结构**:
- `src/lib.rs` - 完整的 TLS 传输实现
- `Cargo.toml` - 依赖配置（tokio-rustls, rustls-pemfile）

---

### rystra-transport-quic/  `规划`

**功能**: QUIC 传输插件

**说明**: 基于 QUIC 协议的传输层实现，提供低延迟、多路复用的安全传输。

**规划特性**:
- 0-RTT 连接建立
- 内置 TLS 1.3 加密
- 多路复用流
- 连接迁移支持

---

## auth/ - 认证插件组

认证插件负责客户端身份验证，实现 `AuthPlugin` trait。

### rystra-auth-token/  `✅ MVP`

**功能**: Token 认证插件

**说明**: 基于静态 Token 的简单认证方案。

**核心组件**:
- `TokenAuthPlugin` - 插件主体，实现 `AuthPlugin` trait

**主要方法**:
- `new()` - 创建空的认证插件
- `with_tokens(tokens)` - 使用预设 Token 列表创建
- `add_token(token)` - 动态添加有效 Token
- `remove_token(token)` - 移除 Token
- `verify(token)` - 验证 Token 是否有效

**文件结构**:
- `src/lib.rs` - 完整的 Token 认证实现
- `Cargo.toml` - 依赖配置

---

### rystra-auth-mtls/  `规划`

**功能**: mTLS 双向认证插件

**说明**: 基于客户端证书的双向 TLS 认证，提供更高安全级别。

**规划特性**:
- 客户端证书验证
- 证书吊销列表 (CRL) 支持
- 证书链验证

---

## hook/ - 钩子插件组

钩子插件提供请求/响应处理过程中的扩展点。

### rystra-hook-rate/  `规划`

**功能**: 速率限制钩子

**说明**: 对代理请求进行速率限制，防止过载和滥用。

**规划特性**:
- 令牌桶算法
- 按 IP/Token 限流
- 动态调整限流阈值
- 限流统计和监控

---

## mux/ - 多路复用插件组

多路复用插件在单个连接上实现多个逻辑流。

### rystra-mux-smux/  `规划`

**功能**: SMUX 多路复用插件

**说明**: 基于 SMUX 协议实现连接多路复用，减少连接开销。

**规划特性**:
- 单连接多流复用
- 流量控制
- 心跳保活
- 与 frp 兼容的 SMUX 实现

---

## 插件开发指南

### 实现传输层插件

实现 `TransportPlugin` trait:

```rust
#[async_trait]
impl TransportPlugin for MyTransportPlugin {
    fn name(&self) -> &'static str { "my-transport" }
    async fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>>;
    async fn connect(&self, addr: &str) -> Result<Box<dyn TransportStream>>;
}
```

### 实现认证插件

实现 `AuthPlugin` trait:

```rust
#[async_trait]
impl AuthPlugin for MyAuthPlugin {
    fn name(&self) -> &'static str { "my-auth" }
    async fn verify(&self, token: &str) -> Result<bool>;
}
```

---

## 状态说明

| 状态 | 含义 |
|------|------|
| ✅ MVP | 最小可行产品，核心功能已实现 |
| ✅ 已完成 | 功能完整，可用于生产 |
| 规划 | 计划开发，尚未实现 |
