use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rystra_auth_token::TokenAuthPlugin;
use rystra_config::ServerConfig;
use rystra_core::{read_message, write_message, ConnectionState, ControlConnection, ProxyEntry, ProxyManager};
use rystra_observe::{error, info, warn};
use rystra_plugin::{AuthPlugin, TransportPlugin, TransportStream};
use rystra_proto::{AuthResponse, Message, OpenStream, RegisterProxyResponse, PROTOCOL_VERSION};
use rystra_runtime::ReunitedStream;
use rystra_transport_tcp::TcpTransportPlugin;
use rystra_transport_tls::TlsTransportPlugin;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

static STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

type ClientSenders = Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>;
type StreamWaiters = Arc<Mutex<HashMap<u64, oneshot::Sender<Box<dyn TransportStream>>>>>;
type DynTransportPlugin = Arc<dyn TransportPlugin>;
type DynReader = ReadHalf<Box<dyn TransportStream>>;
type DynWriter = WriteHalf<Box<dyn TransportStream>>;

/// 将读写半部重新组合为一个完整的 TransportStream


#[tokio::main]
async fn main() {
    // 开发模式下
    let config = if cfg!(debug_assertions) {
        // 开发模式下
        ServerConfig::load_from_file("./crates/rystra-config/server.toml").unwrap()
    } else if cfg!(target_os = "linux") || cfg!(target_os = "windows") {
        // 生产模式下
        ServerConfig::load_from_file("./server.toml").unwrap()
    } else {
        // 其他情况下
        ServerConfig::load_from_file("./crates/rystra-config/server.toml").unwrap()
    };
    rystra_observe::init_with_level(&config.log_level);
    info!("rystra-server starting...");
    info!(?config, "config loaded");

    // 根据配置创建 Transport 插件
    let transport: DynTransportPlugin = if config.tls.enabled {
        info!("TLS enabled, loading certificates...");
        info!(cert_path = %config.tls.cert_path, key_path = %config.tls.key_path, "certificate paths");

        // 检查证书文件是否存在
        if !std::path::Path::new(&config.tls.cert_path).exists() {
            error!(path = %config.tls.cert_path, "certificate file not found");
            error!("falling back to TCP");
            Arc::new(TcpTransportPlugin::new())
        } else if !std::path::Path::new(&config.tls.key_path).exists() {
            error!(path = %config.tls.key_path, "key file not found");
            error!("falling back to TCP");
            Arc::new(TcpTransportPlugin::new())
        } else {
            match TlsTransportPlugin::new_server(&config.tls.cert_path, &config.tls.key_path) {
                Ok(tls) => {
                    info!("TLS transport initialized successfully");
                    Arc::new(tls)
                }
                Err(e) => {
                    error!(error = %e, "failed to initialize TLS, falling back to TCP");
                    Arc::new(TcpTransportPlugin::new())
                }
            }
        }
    } else {
        info!("TLS disabled, using TCP transport");
        Arc::new(TcpTransportPlugin::new())
    };

    // 将配置放入 Arc<RwLock> 以支持运行时重新加载
    let config = Arc::new(RwLock::new(config));

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            error!(error = %e, "failed to listen for ctrl+c");
            return;
        }
        info!("shutdown signal received");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    // 启动 HTTP 管理服务器
    let config_clone = config.clone();
    let shutdown_web = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = run_web_server(config_clone, shutdown_web).await {
            error!(error = %e, "web server error");
        }
    });

    let auth = TokenAuthPlugin::with_tokens(vec!["secret-token".to_string()]);
    let proxy_manager = Arc::new(ProxyManager::new());
    let client_senders: ClientSenders = Arc::new(Mutex::new(HashMap::new()));
    let stream_waiters: StreamWaiters = Arc::new(Mutex::new(HashMap::new()));

    let bind_addr = {
        let cfg = config.read().await;
        cfg.bind_addr.clone()
    };
    let bind_port = {
        let cfg = config.read().await;
        cfg.bind_port
    };
    let heartbeat_timeout = {
        let cfg = config.read().await;
        cfg.heartbeat_timeout
    };

    let addr = format!("{}:{}", bind_addr, bind_port);

    // 使用 Transport 插件启动监听器
    let listener = match transport.listen(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to start listener");
            return;
        }
    };
    info!(addr = %addr, transport = %transport.name(), "listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("shutting down");
            break;
        }

        let accept = tokio::select! {
            r = listener.accept() => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(Ok(stream)) = accept {
            info!("new connection accepted");
            let auth = auth.clone();
            let pm = proxy_manager.clone();
            let cs = client_senders.clone();
            let sw = stream_waiters.clone();
            let shutdown = shutdown.clone();
            let transport = transport.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &auth, &pm, &cs, &sw, shutdown, heartbeat_timeout, transport).await {
                    error!(error = %e, "connection error");
                }
            });
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    info!("server stopped");
}

async fn handle_connection(
    stream: Box<dyn TransportStream>,
    auth: &TokenAuthPlugin,
    proxy_manager: &Arc<ProxyManager>,
    client_senders: &ClientSenders,
    stream_waiters: &StreamWaiters,
    shutdown: Arc<AtomicBool>,
    heartbeat_timeout: u64,
    transport: DynTransportPlugin,
) -> rystra_model::Result<()> {
    // 使用 tokio::io::split 分割流（支持任意 AsyncRead + AsyncWrite）
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let first_msg = read_message(&mut reader).await?;

    match first_msg {
        Message::Hello(hello) => {
            handle_control(reader, writer, hello, auth, proxy_manager, client_senders, stream_waiters, shutdown, heartbeat_timeout, transport).await
        }
        Message::StreamReady(ready) => {
            info!(stream_id = ready.stream_id, "data stream ready");
            // 将读写半部，重新组合为一个完整的流
            let stream = Box::new(ReunitedStream::new(reader.into_inner(), writer));
            if let Some(tx) = stream_waiters.lock().await.remove(&ready.stream_id) {
                let _ = tx.send(stream);
            }
            Ok(())
        }
        _ => {
            warn!(?first_msg, "unexpected first message");
            Ok(())
        }
    }
}

async fn handle_control(
    mut reader: BufReader<DynReader>,
    writer: DynWriter,
    hello: rystra_proto::Hello,
    auth: &TokenAuthPlugin,
    proxy_manager: &Arc<ProxyManager>,
    client_senders: &ClientSenders,
    stream_waiters: &StreamWaiters,
    shutdown: Arc<AtomicBool>,
    heartbeat_timeout: u64,
    _transport: DynTransportPlugin,
) -> rystra_model::Result<()> {
    let writer = Arc::new(Mutex::new(writer));
    let mut conn = ControlConnection::new();

    if hello.version != PROTOCOL_VERSION {
        warn!(conn_id = conn.id, "version mismatch");
        return Ok(());
    }

    conn.set_client_id(hello.client_id.clone());
    conn.transition_to(ConnectionState::Authenticating);

    // 创建一个容量为32的消息通道，用于异步发送消息给客户端
    let (tx, mut rx) = mpsc::channel::<Message>(32);
    // 将发送器添加到全局客户端发送器集合中，以客户端ID作为键
    client_senders.lock().await.insert(hello.client_id.clone(), tx.clone());

    info!(conn_id = conn.id, client_id = %hello.client_id, "control connection, waiting auth");

    let writer_clone = writer.clone();
    // 启动一个异步任务，持续从rx接收消息并写入客户端
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // 锁定写入器进行线程安全访问
            let mut w = writer_clone.lock().await;
            // 将消息写入客户端，出错则退出循环
            if write_message(&mut *w, &msg).await.is_err() {
                break;
            }
        }
    });

    let mut last_heartbeat = Instant::now();
    let timeout_duration = std::time::Duration::from_secs(heartbeat_timeout);

    // 主循环：处理来自客户端的各种消息
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // 如果连接已就绪且心跳超时，则断开连接
        if conn.is_ready() && last_heartbeat.elapsed() > timeout_duration {
            warn!(conn_id = conn.id, "heartbeat timeout");
            break;
        }

        // 尝试从读取器中读取消息，或等待1秒
        let read = tokio::select! {
            r = read_message(&mut reader) => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => None,
        };

        let msg = match read {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                error!(conn_id = conn.id, error = %e, "read error");
                break;
            }
            None => continue,
        };

        match msg {
            Message::AuthRequest(auth_req) => {
                let success = auth.verify(&auth_req.token).await?;
                let resp = Message::AuthResponse(AuthResponse {
                    success,
                    message: if success { None } else { Some("invalid token".to_string()) },
                });
                let mut w = writer.lock().await;
                write_message(&mut *w, &resp).await?;

                if success {
                    conn.transition_to(ConnectionState::Ready);
                    last_heartbeat = Instant::now();
                    info!(conn_id = conn.id, "authenticated");
                } else {
                    warn!(conn_id = conn.id, "auth failed");
                    break;
                }
            }

            Message::RegisterProxy(reg) => {
                if !conn.is_ready() { continue; }
                last_heartbeat = Instant::now();
                let client_id = conn.client_id.clone().unwrap_or_default();
                let entry = ProxyEntry {
                    name: reg.name.clone(),
                    remote_port: reg.remote_port,
                    local_addr: reg.local_addr,
                    local_port: reg.local_port,
                    client_id: client_id.clone(),
                };
                let pm = proxy_manager.clone();
                let cs = client_senders.clone();
                let sw = stream_waiters.clone();
                let name = reg.name.clone();
                let port = reg.remote_port;
                let sd = shutdown.clone();

                let success = pm.register(entry);
                if success {
                    info!(proxy = %name, port = port, "proxy registered");
                    tokio::spawn(async move {
                        if let Err(e) = run_proxy_listener(port, name, client_id, cs, sw, sd).await {
                            error!(error = %e, "proxy listener error");
                        }
                    });
                }

                let resp = Message::RegisterProxyResponse(RegisterProxyResponse {
                    name: reg.name,
                    success,
                    message: if success { None } else { Some("already exists".to_string()) },
                });
                let mut w = writer.lock().await;
                write_message(&mut *w, &resp).await?;
            }

            Message::Heartbeat => {
                last_heartbeat = Instant::now();
                let mut w = writer.lock().await;
                write_message(&mut *w, &Message::Heartbeat).await?;
            }

            _ => {}
        }
    }

    if let Some(cid) = &conn.client_id {
        client_senders.lock().await.remove(cid);
        proxy_manager.unregister_by_client(cid);
    }
    info!(conn_id = conn.id, "control connection closed");
    Ok(())
}

/// HTTP 管理服务器，处理 /reload 请求
async fn run_web_server(
    config: Arc<RwLock<ServerConfig>>,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let (addr, port, user, password) = {
        let cfg = config.read().await;
        (
            cfg.web_server.addr.clone(),
            cfg.web_server.port,
            cfg.web_server.user.clone(),
            cfg.web_server.password.clone(),
        )
    };

    let bind_addr = format!("{}:{}", addr, port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "web management server listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let accept = tokio::select! {
            r = listener.accept() => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(Ok((stream, _))) = accept {
            let config_clone = config.clone();
            let user_clone = user.clone();
            let password_clone = password.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    handle_web_request(
                        req,
                        config_clone.clone(),
                        user_clone.clone(),
                        password_clone.clone(),
                    )
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    error!(error = %e, "http connection error");
                }
            });
        }
    }

    Ok(())
}

/// 处理 HTTP 请求
async fn handle_web_request(
    req: Request<Incoming>,
    config: Arc<RwLock<ServerConfig>>,
    expected_user: String,
    expected_password: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    // 简单的基本认证检查
    if let Some(auth_header) = req.headers().get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(basic) = auth_str.strip_prefix("Basic ")
        && let Ok(decoded) = base64_decode(basic) {
        let parts: Vec<&str> = decoded.split(':').collect();
        if parts.len() == 2 && parts[0] == expected_user && parts[1] == expected_password {
            // 认证成功，处理请求
            return handle_authenticated_request(path, config).await;
        }
    }

    // 认证失败
    let response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"Rystra Management\"")
        .body(Full::new(Bytes::from("Unauthorized")))
        .unwrap();
    Ok(response)
}

/// 处理已认证的请求
async fn handle_authenticated_request(
    path: &str,
    config: Arc<RwLock<ServerConfig>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match path {
        "/reload" => {
            info!("received reload request");

            // 重新加载配置文件
            match ServerConfig::load_from_file("./crates/rystra-config/server.toml") {
                Ok(new_config) => {
                    let mut cfg = config.write().await;
                    *cfg = new_config;
                    info!("configuration reloaded successfully");

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(
                            serde_json::json!({
                                "status": "success",
                                "message": "Configuration reloaded successfully"
                            })
                                .to_string(),
                        )))
                        .unwrap();
                    Ok(response)
                }
                Err(e) => {
                    error!(error = %e, "failed to reload configuration");
                    let response = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from(
                            serde_json::json!({
                                "status": "error",
                                "message": format!("Failed to reload: {}", e)
                            })
                                .to_string(),
                        )))
                        .unwrap();
                    Ok(response)
                }
            }
        }
        "/health" => {
            // 健康检查端点
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(
                    serde_json::json!({
                        "status": "ok"
                    })
                        .to_string(),
                )))
                .unwrap();
            Ok(response)
        }
        _ => {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap();
            Ok(response)
        }
    }
}

/// 简单的 Base64 解码
fn base64_decode(input: &str) -> Result<String, ()> {
    use std::str;

    // 简单实现，实际生产应使用 base64 crate
    let bytes = match base64_decode_bytes(input) {
        Ok(b) => b,
        Err(_) => return Err(()),
    };

    match str::from_utf8(&bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(()),
    }
}

fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, ()> {
    // 使用标准库的简单实现
    let table: Vec<u8> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .bytes()
        .collect();

    let mut result = Vec::new();
    let chars: Vec<char> = input.chars().filter(|c| !c.is_whitespace()).collect();

    let mut i = 0;
    while i < chars.len() {
        let mut buf = [0u8; 4];
        for j in 0..4 {
            if i + j < chars.len() && chars[i + j] != '=' {
                if let Some(pos) = table.iter().position(|&x| x == chars[i + j] as u8) {
                    buf[j] = pos as u8;
                } else {
                    return Err(());
                }
            }
        }

        result.push((buf[0] << 2) | (buf[1] >> 4));
        if i + 2 < chars.len() && chars[i + 2] != '=' {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if i + 3 < chars.len() && chars[i + 3] != '=' {
            result.push((buf[2] << 6) | buf[3]);
        }

        i += 4;
    }

    Ok(result)
}

async fn run_proxy_listener(
    port: u16,
    proxy_name: String,
    client_id: String,
    client_senders: ClientSenders,
    stream_waiters: StreamWaiters,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(proxy = %proxy_name, addr = %addr, "proxy listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let accept = tokio::select! {
            r = listener.accept() => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(Ok((user_stream, user_addr))) = accept {
            info!(proxy = %proxy_name, user = %user_addr, "user connected");

            let stream_id = STREAM_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = oneshot::channel();
            stream_waiters.lock().await.insert(stream_id, tx);

            let msg = Message::OpenStream(OpenStream {
                proxy_name: proxy_name.clone(),
                stream_id,
            });

            if let Some(sender) = client_senders.lock().await.get(&client_id) {
                let _ = sender.send(msg).await;
            }

            let pn = proxy_name.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
                    Ok(Ok(client_stream)) => {
                        info!(stream_id = stream_id, "relay started");
                        // 使用 tokio::io::split 支持任意 AsyncRead + AsyncWrite
                        let (mut ur, mut uw) = tokio::io::split(user_stream);
                        let (mut cr, mut cw) = tokio::io::split(client_stream);
                        let _ = tokio::try_join!(
                            tokio::io::copy(&mut ur, &mut cw),
                            tokio::io::copy(&mut cr, &mut uw)
                        );
                        info!(stream_id = stream_id, "relay closed");
                    }
                    _ => {
                        warn!(proxy = %pn, stream_id = stream_id, "stream timeout");
                    }
                }
            });
        }
    }

    Ok(())
}