# Rystra - 基于 Rust 的高性能反向代理系统

下一代内网穿透与反向代理解决方案，旨在解决现有 frp 等工具的不足，提供更高效、安全、易用的体验。

## 项目愿景

Rystra 是一个现代化的反向代理系统，相比现有的 frp，具有以下显著优势：
- **性能卓越**：基于 Rust 异步生态，零拷贝技术优化数据传输
- **安全性强**：内置多种认证方式，端到端加密，细粒度权限控制
- **扩展性强**：插件化架构，支持自定义协议和功能扩展
- **运维友好**：内置 Tauri 桌面管理面板，实时监控，动态配置更新
- **资源占用低**：内存安全，CPU 占用率低，适合长期运行

## 核心架构设计

### 1.1 架构模式
采用经典的客户端-服务端架构，结合共享组件设计模式，实现代码复用和模块化开发。

### 1.2 共享组件设计
项目采用多 crate 结构，将通用功能提取到共享组件中，避免代码重复，提高维护性。

#### **1.3 核心模块划分**

1. **`control-plane`（控制平面）**：
   - 负责管理与调度客户端的连接与配置
   - 包含用户认证、配置解析、管理面板等功能
   - 支持动态配置热更新，无需重启服务
   - 提供 REST API 和 WebSocket 接口供管理面板调用

2. **`data-plane`（数据平面）**：
   - 负责数据转发与隧道的建立
   - 支持 TCP/UDP/HTTP/HTTPS/WebSocket 等多种协议
   - 实现零拷贝数据传输，优化带宽利用率
   - 内置智能负载均衡和故障转移机制

3. **`auth`（认证）**：
   - 支持多种认证方式：JWT Token、OIDC、API Key、证书认证
   - 实现 RBAC（角色访问控制）系统，精确控制用户权限
   - 支持多租户隔离，满足企业级需求
   - 提供细粒度的访问控制策略

4. **`dashboard`（管理面板）**：
   - 基于 Tauri + Axum + Vue3 构建的现代化桌面应用程序
   - 提供隧道管理、实时流量监控、日志查看、用户管理等功能
   - 支持多语言国际化
   - 实现可视化配置编辑器

5. **`protocol`（通信协议）**：
   - 自研高性能通信协议，减少握手延迟
   - 支持多路复用，单连接承载多个隧道
   - 内置压缩算法，提升传输效率
   - 实现智能心跳和自动重连机制

6. **`plugin`（插件系统）**：
   - 支持动态加载插件，扩展功能
   - 提供钩子机制，在关键节点插入自定义逻辑
   - 允许第三方开发者贡献插件

7. **`monitoring`（监控告警）**：
   - 集成 Prometheus 指标收集
   - 实时监控隧道状态、流量统计、性能指标
   - 支持告警通知（邮件、Webhook）

8. **`utils`（公共工具）**：
   - 日志记录、配置解析、加密工具、网络工具等

#### **1.4 改进亮点（相较于 frp）**

1. **性能优化**：
   - Rust 无 GC 语言特性，避免运行时性能抖动
   - 异步 I/O 模型，高并发下资源消耗更低
   - 零拷贝数据传输，减少 CPU 开销

2. **安全性增强**：
   - 默认启用端到端加密
   - 更丰富的认证方式选择
   - 细粒度权限控制，支持 ACL 规则

3. **易用性提升**：
   - 基于 Tauri 的桌面管理界面，用户体验更佳
   - 支持配置文件热更新
   - 更完善的文档和示例

4. **扩展性改进**：
   - 插件化架构，便于功能扩展
   - 模块化设计，支持定制开发
   - 标准化的 API 接口

#### **1.5 整体目录结构**

```
rystra/
├── Cargo.toml                  # 项目依赖配置，包含 workspace 配置
├── Cargo.lock
├── rust-toolchain.toml         # Rust 工具链配置
├── README.md                   # 项目说明
├── LICENSE                     # 许可证文件
├── .gitignore
├── config/                     # 配置文件
│   ├── server.toml             # 服务端默认配置
│   └── client.toml             # 客户端默认配置
├── examples/                   # 示例配置
│   ├── http_tunnel.toml
│   ├── tcp_tunnel.toml
│   └── udp_tunnel.toml
├── scripts/                    # 脚本文件
│   ├── build.sh
│   └── install.sh
├── frontend/                   # Tauri 前端管理面板
│   ├── src/                    # 前端源码
│   │   ├── main.js             # Tauri 主入口
│   │   ├── App.vue             # 前端主应用
│   │   ├── components/         # 前端组件
│   │   │   ├── Dashboard.vue
│   │   │   ├── TunnelManager.vue
│   │   │   ├── Monitoring.vue
│   │   │   └── Settings.vue
│   │   ├── styles/             # 样式文件
│   │   └── assets/             # 静态资源
│   ├── src-tauri/              # Tauri 配置
│   │   ├── Cargo.toml
│   │   ├── tauri.conf.json     # Tauri 配置文件
│   │   └── js/                 # Tauri 前端接口
│   │       └── api.js
│   ├── package.json
│   ├── vite.config.js
│   └── jsconfig.json
├── crates/                     # 多 crate 项目结构
│   ├── rystra-core/            # 核心共享库
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config/         # 共享配置模块
│   │       │   ├── mod.rs
│   │       │   ├── common_config.rs  # 通用配置结构
│   │       │   └── validation.rs     # 配置验证
│   │       ├── protocol/       # 通信协议共享模块
│   │       │   ├── mod.rs
│   │       │   ├── message.rs          # 消息定义
│   │       │   ├── codec.rs            # 编解码器
│   │       │   ├── handshake.rs        # 握手协议
│   │       │   └── types.rs            # 协议类型定义
│   │       ├── auth/           # 认证共享模块
│   │       │   ├── mod.rs
│   │       │   ├── token.rs            # Token 相关
│   │       │   ├── credentials.rs      # 凭据管理
│   │       │   └── models.rs           # 认证模型
│   │       ├── models/         # 数据模型共享
│   │       │   ├── mod.rs
│   │       │   ├── tunnel.rs           # 隧道模型
│   │       │   ├── user.rs             # 用户模型
│   │       │   └── session.rs          # 会话模型
│   │       ├── utils/          # 公共工具
│   │       │   ├── mod.rs
│   │       │   ├── crypto.rs           # 加密工具
│   │       │   ├── logger.rs           # 日志工具
│   │       │   ├── net.rs              # 网络工具
│   │       │   ├── helpers.rs          # 辅助函数
│   │       │   └── error.rs            # 错误定义
│   │       ├── network/        # 网络共享组件
│   │       │   ├── mod.rs
│   │       │   ├── connection.rs       # 连接管理
│   │       │   ├── stream.rs           # 流处理
│   │       │   └── multiplexer.rs      # 多路复用器
│   │       └── metrics/        # 指标共享
│   │           ├── mod.rs
│   │           ├── common.rs           # 通用指标
│   │           └── registry.rs         # 指标注册
│   ├── rystra-server/          # 服务端二进制
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         # 服务端主入口
│   │       └── server.rs       # 服务端实现（导入并使用8个核心模块）
│   ├── rystra-client/          # 客户端二进制
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         # 客户端主入口
│   │       └── client.rs       # 客户端实现（导入并使用8个核心模块）
│   └── rystra-shared/          # 极简共享类型（仅用于编译时依赖）
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── common_types.rs
└── docs/                       # 文档
    ├── getting-started.md
    ├── configuration.md
    └── api-reference.md
```

#### **1.6 共享组件详解**

共享组件是本项目架构的核心，通过将通用功能提取到 `rystra-core` crate 中，实现客户端和服务端的代码复用：

1. **协议层共享**：定义统一的通信协议，确保客户端和服务端之间的兼容性
2. **认证模型共享**：统一的认证结构和验证逻辑
3. **配置模型共享**：基础配置结构定义
4. **网络工具共享**：连接管理、流处理等通用网络操作
5. **错误处理共享**：统一的错误类型定义
6. **日志和指标共享**：统一的监控和日志记录接口

#### **1.7 服务端目录结构详解**

服务端（rystra-server）主要负责接收客户端连接、管理隧道映射、提供管理接口等。
服务端通过导入rystra-core中的共享组件及相应模块来实现功能。

```
crates/rystra-server/
├── Cargo.toml                  # 服务端依赖配置
└── src/
    ├── main.rs                 # 服务端主入口
    └── server.rs               # 服务端实现（导入并使用8个核心模块）
```

#### **1.8 客户端目录结构详解**

客户端（rystra-client）主要负责连接服务端、建立本地服务监听、数据转发等。
客户端通过导入rystra-core中的共享组件及相应模块来实现功能。

```
crates/rystra-client/
├── Cargo.toml                  # 客户端依赖配置
└── src/
    ├── main.rs                 # 客户端主入口
    └── client.rs               # 客户端实现（导入并使用8个核心模块）
```

#### **1.9 技术栈**

- **核心语言**：Rust 2024 edition
- **异步运行时**：Tokio
- **Web 框架**：Axum
- **桌面框架**：Tauri
- **前端框架**：Vue3 + JavaScript
- **构建工具**：Vite
- **序列化**：Serde
- **日志系统**：Tracing
- **数据库**：SQLite（可选，用于持久化存储）
- **监控**：Prometheus + Grafana

#### **1.10 快速开始**

```bash
# 构建服务端
cargo build --release -p rystra-server

# 构建客户端
cargo build --release -p rystra-client

# 构建管理面板
cd frontend && npm install && npm run tauri build

# 运行服务端
./target/release/rystra-server -c config/server.toml

# 运行客户端
./target/release/rystra-client -c config/client.toml
```

#### **1.11 架构优化与改进**

##### 1.11.1 错误处理一致性
项目采用统一的错误处理机制，定义了标准化的错误类型枚举，确保各模块错误处理的一致性：

```rust
#[derive(Debug)]
pub enum CoreError {
    NetworkError(String),
    AuthenticationError(String),
    ConfigurationError(String),
    // ... 其他错误类型
}
```

##### 1.11.2 配置热更新机制
实现了配置文件的热更新功能，无需重启服务即可动态更新配置：
- 配置变更监控
- 无缝配置切换
- 配置验证机制

##### 1.11.3 性能监控
集成了全面的性能监控指标：
- 连接数统计
- 数据传输量监控
- 请求响应时间
- 系统资源使用情况

##### 1.11.4 测试策略
项目采用全面的测试策略，包括：
- 单元测试
- 集成测试
- 端到端测试
- 性能测试

使用 [dev-dependencies] 中的 `tokio-test` 和 `assert_matches` 等工具支持异步测试和断言匹配。

#### **1.12 项目架构设计规范**

根据项目要求，架构设计遵循以下规范：
- 针对 frp 缺点进行优化，重点提升易用性和后期扩展性
- 采用插件化、模块化设计，分离控制平面与数据平面
- 客户端和服务端目录结构精简，避免过多子目录层级
- 统一错误处理机制，确保各模块一致性
- 使用 Rust 2024 版本特性，提升代码质量和性能
- 配置 workspace 使用 resolver = "2"，统一管理依赖和构建