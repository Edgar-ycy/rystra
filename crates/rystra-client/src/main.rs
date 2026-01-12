use rystra_config::ClientConfig;
use rystra_core::{read_message, write_message};
use rystra_observe::{error, info, warn};
use rystra_proto::{AuthRequest, Hello, Message, RegisterProxy, StreamReady, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let config = ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap();
    rystra_observe::init_with_level(&config.log_level);
    info!("rystra-client starting...");
    info!(?config, "config loaded");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        info!("shutdown signal received");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    let mut retry = 0u32;

    while !shutdown.load(Ordering::SeqCst) {
        match run(&config, shutdown.clone()).await {
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

async fn run(config: &ClientConfig, shutdown: Arc<AtomicBool>) -> rystra_model::Result<()> {
    let server_addr = format!("{}:{}", config.server_addr, config.server_port);
    info!(addr = %server_addr, "connecting");

    let stream = TcpStream::connect(&server_addr).await?;
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));

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

    let mut proxy_map: HashMap<String, (String, u16)> = HashMap::new();
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
        proxy_map.insert(p.name.clone(), (p.local_ip.clone(), p.local_port));

        let resp = read_message(&mut reader).await?;
        info!(?resp, "proxy registered");
    }

    info!("entering main loop");

    let writer_hb = writer.clone();
    let shutdown_hb = shutdown.clone();
    tokio::spawn(async move {
        while !shutdown_hb.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if shutdown_hb.load(Ordering::SeqCst) { break; }
            let mut w = writer_hb.lock().await;
            if write_message(&mut *w, &Message::Heartbeat).await.is_err() {
                break;
            }
        }
    });

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let read = tokio::select! {
            r = read_message(&mut reader) => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        let msg = match read {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(e),
            None => continue,
        };

        match msg {
            Message::OpenStream(open) => {
                info!(proxy = %open.proxy_name, stream_id = open.stream_id, "open stream");

                if let Some((local_ip, local_port)) = proxy_map.get(&open.proxy_name) {
                    let local_target = format!("{}:{}", local_ip, local_port);
                    let server_addr = format!("{}:{}", config.server_addr, config.server_port);
                    let stream_id = open.stream_id;

                    tokio::spawn(async move {
                        if let Err(e) = handle_stream(stream_id, &server_addr, &local_target).await {
                            error!(stream_id = stream_id, error = %e, "stream error");
                        }
                    });
                } else {
                    warn!(proxy = %open.proxy_name, "unknown proxy");
                }
            }
            Message::Heartbeat => {}
            _ => {}
        }
    }

    Ok(())
}

async fn handle_stream(stream_id: u64, server_addr: &str, local_target: &str) -> rystra_model::Result<()> {
    let local = TcpStream::connect(local_target).await?;
    let mut server = TcpStream::connect(server_addr).await?;

    let ready = Message::StreamReady(StreamReady { stream_id });
    let json = serde_json::to_string(&ready).unwrap();
    server.write_all(json.as_bytes()).await?;
    server.write_all(b"\n").await?;
    server.flush().await?;

    info!(stream_id = stream_id, "relay started");

    let (mut sr, mut sw) = server.into_split();
    let (mut lr, mut lw) = local.into_split();

    let _ = tokio::try_join!(
        tokio::io::copy(&mut sr, &mut lw),
        tokio::io::copy(&mut lr, &mut sw)
    );

    info!(stream_id = stream_id, "relay closed");
    Ok(())
}