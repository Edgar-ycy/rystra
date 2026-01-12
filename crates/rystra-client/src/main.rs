use rystra_config::ClientConfig;
use rystra_core::{read_message, write_message};
use rystra_observe::{error, info, warn};
use rystra_plugin::TransportPlugin;
use rystra_proto::{AuthRequest, Hello, Message, RegisterProxy, StreamReady, PROTOCOL_VERSION};
use rystra_transport_tcp::TcpTransportPlugin;
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
        if let Err(e) = signal::ctrl_c().await {
            error!(error = %e, "failed to listen for ctrl+c");
            return;
        }
        info!("received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    let mut retry_count = 0;
    let max_retries = 5;

    while !shutdown.load(Ordering::SeqCst) {
        match run_client(&config, shutdown.clone()).await {
            Ok(_) => {
                retry_count = 0;
            }
            Err(e) => {
                error!(error = %e, "client error");
                retry_count += 1;
                if retry_count >= max_retries {
                    error!("max retries reached, exiting");
                    break;
                }
                let delay = std::cmp::min(2u64.pow(retry_count), 30);
                info!(delay = delay, retry = retry_count, "reconnecting in {} seconds", delay);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    info!("client stopped");
}

async fn run_client(config: &ClientConfig, shutdown: Arc<AtomicBool>) -> rystra_model::Result<()> {
    let transport = TcpTransportPlugin::new();
    let server_addr = format!("{}:{}", config.server_addr, config.server_bind_port);
    let data_addr = format!("{}:{}", config.server_addr, config.server_data_port);

    info!(addr = %server_addr, "connecting to server");

    let stream = transport.connect(&server_addr).await?;
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));

    let hello = Message::Hello(Hello {
        client_id: "client-001".to_string(),
        version: PROTOCOL_VERSION,
    });
    {
        let mut w = writer.lock().await;
        write_message(&mut *w, &hello).await?;
    }
    info!("sent Hello");

    let auth = Message::AuthRequest(AuthRequest {
        token: "secret-token".to_string(),
    });
    {
        let mut w = writer.lock().await;
        write_message(&mut *w, &auth).await?;
    }
    info!("sent AuthRequest");

    let resp = read_message(&mut reader).await?;
    info!(?resp, "recv");

    if let Message::AuthResponse(auth_resp) = resp {
        if !auth_resp.success {
            return Err(rystra_model::Error::protocol("auth failed"));
        }
    }

    let mut proxy_map: HashMap<String, (String, u16)> = HashMap::new();
    for proxy in &config.proxies {
        let reg = Message::RegisterProxy(RegisterProxy {
            name: proxy.name.clone(),
            remote_port: proxy.remote_port,
            local_addr: proxy.local_ip.clone(),
            local_port: proxy.local_port,
        });
        {
            let mut w = writer.lock().await;
            write_message(&mut *w, &reg).await?;
        }
        info!(name = %proxy.name, "sent RegisterProxy");

        proxy_map.insert(proxy.name.clone(), (proxy.local_ip.clone(), proxy.local_port));

        let resp = read_message(&mut reader).await?;
        info!(?resp, "recv");
    }

    info!("all proxies registered, entering main loop");

    let writer_clone = writer.clone();
    let shutdown_hb = shutdown.clone();
    tokio::spawn(async move {
        while !shutdown_hb.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if shutdown_hb.load(Ordering::SeqCst) {
                break;
            }
            let mut w = writer_clone.lock().await;
            if write_message(&mut *w, &Message::Heartbeat).await.is_err() {
                break;
            }
            info!("sent Heartbeat");
        }
    });

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("shutdown requested");
            break;
        }

        let read_result = tokio::select! {
            result = read_message(&mut reader) => Some(result),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        let msg = match read_result {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                return Err(e);
            }
            None => continue,
        };

        match msg {
            Message::OpenStream(open) => {
                info!(proxy = %open.proxy_name, stream_id = open.stream_id, "recv OpenStream");

                if let Some((local_addr, local_port)) = proxy_map.get(&open.proxy_name) {
                    let local_target = format!("{}:{}", local_addr, local_port);
                    let stream_id = open.stream_id;
                    let data_addr = data_addr.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_data_stream(stream_id, &data_addr, &local_target).await {
                            error!(stream_id = stream_id, error = %e, "data stream error");
                        }
                    });
                } else {
                    warn!(proxy = %open.proxy_name, "unknown proxy");
                }
            }

            Message::Heartbeat => {
                info!("recv Heartbeat");
            }

            _ => {
                info!(?msg, "recv");
            }
        }
    }

    Ok(())
}

async fn handle_data_stream(
    stream_id: u64,
    data_addr: &str,
    local_target: &str,
) -> rystra_model::Result<()> {
    info!(stream_id = stream_id, target = %local_target, "connecting local");
    let local_stream = TcpStream::connect(local_target).await?;

    info!(stream_id = stream_id, addr = %data_addr, "connecting data port");
    let mut server_stream = TcpStream::connect(data_addr).await?;

    let ready = StreamReady { stream_id };
    let json = serde_json::to_string(&Message::StreamReady(ready)).unwrap();
    server_stream.write_all(json.as_bytes()).await?;
    server_stream.write_all(b"\n").await?;
    server_stream.flush().await?;

    info!(stream_id = stream_id, "relay started");

    let (mut sr, mut sw) = server_stream.into_split();
    let (mut lr, mut lw) = local_stream.into_split();

    let s2l = tokio::io::copy(&mut sr, &mut lw);
    let l2s = tokio::io::copy(&mut lr, &mut sw);

    let _ = tokio::try_join!(s2l, l2s);

    info!(stream_id = stream_id, "relay closed");
    Ok(())
}