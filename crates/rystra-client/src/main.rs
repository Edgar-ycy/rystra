use rystra_config::{ClientConfig, TransportKind};
use rystra_core::{read_message, write_message};
use rystra_observe::{error, info, warn};
use rystra_plugin::{TransportPlugin, TransportStream};
use rystra_proto::{AuthRequest, Hello, Message, RegisterProxy, StreamReady, PROTOCOL_VERSION};
use rystra_transport_tcp::TcpTransportPlugin;
use rystra_transport_tls::TlsTransportPlugin;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncWriteExt, BufReader, WriteHalf};
use tokio::signal;
use tokio::sync::Mutex;

type DynTransportPlugin = Arc<dyn TransportPlugin>;
type DynWriter = WriteHalf<Box<dyn TransportStream>>;

#[tokio::main]
async fn main() {
    // let config = ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap();
    let config = if cfg!(debug_assertions) {
        ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap()
    } else if cfg!(target_os = "linux") || cfg!(target_os = "windows")  {
        ClientConfig::load_from_file("./client.toml").unwrap()
    } else {
        ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap()
    };
    rystra_observe::init_with_level(&config.log_level);
    info!("rystra-client starting...");
    info!(?config, "config loaded");

    // 根据配置创建 Transport 插件
    let transport: DynTransportPlugin = if config.tls.enabled {
        info!("TLS enabled");
        if config.tls.insecure_skip_verify {
            info!("TLS insecure mode (skip certificate verification)");
            match TlsTransportPlugin::new_client_insecure() {
                Ok(tls) => {
                    info!("TLS transport initialized (insecure mode)");
                    Arc::new(tls)
                }
                Err(e) => {
                    error!(error = %e, "failed to initialize TLS, falling back to TCP");
                    Arc::new(TcpTransportPlugin::new())
                }
            }
        } else {
            info!("TLS secure mode, loading CA certificate...");
            info!(ca_cert_path = %config.tls.ca_cert_path, "CA certificate path");
            
            // 检查 CA 证书文件是否存在
            if !std::path::Path::new(&config.tls.ca_cert_path).exists() {
                error!(path = %config.tls.ca_cert_path, "CA certificate file not found");
                error!("falling back to TCP");
                Arc::new(TcpTransportPlugin::new())
            } else {
                match TlsTransportPlugin::new_client(&config.tls.ca_cert_path) {
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
        }
    } else {
        info!("TLS disabled, using TCP transport");
        Arc::new(TcpTransportPlugin::new())
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        info!("shutdown signal received");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    let mut retry = 0u32;

    while !shutdown.load(Ordering::SeqCst) {
        match run(&config, shutdown.clone(), transport.clone()).await {
            Ok(_) => retry = 0,
            Err(e) => {
                error!(error = %e, "client error");
                retry += 1;
                if retry > 5 {
                    error!("max retries, exiting");
                    break;
                }
                let delay = std::cmp::min(2u64.pow(retry), 30);
                info!(delay = delay, "reconnecting...");
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }
    }

    info!("client stopped");
}

async fn run(config: &ClientConfig, shutdown: Arc<AtomicBool>, transport: DynTransportPlugin) -> rystra_model::Result<()> {
    let server_addr = format!("{}:{}", config.server_addr, config.server_port);
    info!(addr = %server_addr, transport = %transport.name(), "connecting");

    // 使用 Transport 插件连接服务器
    let stream = transport.connect(&server_addr).await?;
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let writer: Arc<Mutex<DynWriter>> = Arc::new(Mutex::new(writer));

    {
        let mut w = writer.lock().await;
        let hello = Message::Hello(Hello {
            client_id: "client-001".to_string(),
            version: PROTOCOL_VERSION,
        });
        write_message(&mut *w, &hello).await?;
    }
    info!("sent Hello");

    {
        let mut w = writer.lock().await;
        let auth = Message::AuthRequest(AuthRequest {
            token: "secret-token".to_string(),
        });
        write_message(&mut *w, &auth).await?;
    }
    info!("sent AuthRequest");

    let resp = read_message(&mut reader).await?;
    if let Message::AuthResponse(r) = resp {
        if !r.success {
            return Err(rystra_model::Error::protocol("auth failed"));
        }
        info!("authenticated");
    }

    let proxy_map: Arc<Mutex<HashMap<String, (String, u16, TransportKind)>>> = Arc::new(Mutex::new(HashMap::new()));
    for p in &config.proxies {
        let reg = Message::RegisterProxy(RegisterProxy {
            name: p.name.clone(),
            remote_port: p.remote_port,
            local_addr: p.local_ip.clone(),
            local_port: p.local_port,
        });
        {
            let mut w = writer.lock().await;
            write_message(&mut *w, &reg).await?;
        }
        proxy_map.lock().await.insert(p.name.clone(), (p.local_ip.clone(), p.local_port, p.kind.clone()));

        let resp = read_message(&mut reader).await?;
        info!(?resp, "proxy registered");
    }

    info!("entering main loop");

    let last_heartbeat_resp = Arc::new(Mutex::new(Instant::now()));
    let heartbeat_timeout = std::time::Duration::from_secs(config.heartbeat_timeout);
    let heartbeat_interval = config.heartbeat_interval;

    let writer_hb = writer.clone();
    let shutdown_hb = shutdown.clone();
    tokio::spawn(async move {
        while !shutdown_hb.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(heartbeat_interval)).await;
            if shutdown_hb.load(Ordering::SeqCst) { break; }
            let mut w = writer_hb.lock().await;
            if write_message(&mut *w, &Message::Heartbeat).await.is_err() {
                break;
            }
            info!("sent Heartbeat");
        }
    });

    let proxy_map_clone = proxy_map.clone();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        if last_heartbeat_resp.lock().await.elapsed() > heartbeat_timeout {
            warn!("heartbeat response timeout");
            return Err(rystra_model::Error::protocol("heartbeat timeout"));
        }

        let read = tokio::select! {
            r = read_message(&mut reader) => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => None,
        };

        let msg = match read {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(e),
            None => continue,
        };

        match msg {
            Message::OpenStream(open) => {
                info!(proxy = %open.proxy_name, stream_id = open.stream_id, "open stream");

                let transport_info = {
                    let map = proxy_map_clone.lock().await;
                    map.get(&open.proxy_name).cloned()
                };

                if let Some((local_ip, local_port, transport_kind)) = transport_info {
                    let local_target = format!("{}:{}", local_ip, local_port);
                    let server_addr = format!("{}:{}", config.server_addr, config.server_port);
                    let stream_id = open.stream_id;
                    let transport_clone = transport.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_stream(stream_id, &server_addr, &local_target, transport_kind, transport_clone).await {
                            error!(stream_id = stream_id, error = %e, "stream error");
                        }
                    });
                } else {
                    warn!(proxy = %open.proxy_name, "unknown proxy");
                }
            }
            Message::Heartbeat => {
                *last_heartbeat_resp.lock().await = Instant::now();
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_stream(
    stream_id: u64,
    server_addr: &str,
    local_target: &str,
    transport_kind: TransportKind,
    transport: DynTransportPlugin,
) -> rystra_model::Result<()> {
    // 连接本地服务（始终使用 TCP）
    let local = match transport_kind {
        TransportKind::Tcp => {
            tokio::net::TcpStream::connect(local_target).await?
        }
    };

    // 使用 Transport 插件连接 Server（支持 TCP/TLS）
    let mut server = transport.connect(server_addr).await?;

    let ready = Message::StreamReady(StreamReady { stream_id });
    let json = serde_json::to_string(&ready).unwrap();
    server.write_all(json.as_bytes()).await?;
    server.write_all(b"\n").await?;
    server.flush().await?;

    info!(stream_id = stream_id, "relay started");

    // 使用 tokio::io::split 支持任意 AsyncRead + AsyncWrite
    let (mut sr, mut sw) = tokio::io::split(server);
    let (mut lr, mut lw) = tokio::io::split(local);

    let _ = tokio::try_join!(
        tokio::io::copy(&mut sr, &mut lw),
        tokio::io::copy(&mut lr, &mut sw)
    );

    info!(stream_id = stream_id, "relay closed");
    Ok(())
}