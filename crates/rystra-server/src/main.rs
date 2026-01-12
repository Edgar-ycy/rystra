use rystra_auth_token::TokenAuthPlugin;
use rystra_config::ServerConfig;
use rystra_core::{read_message, write_message, ConnectionState, ControlConnection, ProxyEntry, ProxyManager};
use rystra_observe::{error, info, warn};
use rystra_plugin::AuthPlugin;
use rystra_proto::{AuthResponse, Message, OpenStream, RegisterProxyResponse, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::signal;
use tokio::sync::{mpsc, oneshot, Mutex};

static STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

type ClientSenders = Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>;
type StreamWaiters = Arc<Mutex<HashMap<u64, oneshot::Sender<TcpStream>>>>;

#[tokio::main]
async fn main() {
    let config = ServerConfig::load_from_file("./crates/rystra-config/server.toml").unwrap();
    rystra_observe::init_with_level(&config.log_level);
    info!("rystra-server starting...");
    info!(?config, "config loaded");

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

    let auth = TokenAuthPlugin::with_tokens(vec!["secret-token".to_string()]);
    let proxy_manager = Arc::new(ProxyManager::new());
    let client_senders: ClientSenders = Arc::new(Mutex::new(HashMap::new()));
    let stream_waiters: StreamWaiters = Arc::new(Mutex::new(HashMap::new()));

    let addr = format!("{}:{}", config.bind_addr, config.bind_port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    info!(addr = %addr, "listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("shutting down");
            break;
        }

        let accept = tokio::select! {
            r = listener.accept() => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(Ok((stream, addr))) = accept {
            info!(addr = %addr, "new tcp connection");
            let auth = auth.clone();
            let pm = proxy_manager.clone();
            let cs = client_senders.clone();
            let sw = stream_waiters.clone();
            let shutdown = shutdown.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &auth, &pm, &cs, &sw, shutdown).await {
                    error!(error = %e, "connection error");
                }
            });
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    info!("server stopped");
}

async fn handle_connection(
    stream: TcpStream,
    auth: &TokenAuthPlugin,
    proxy_manager: &Arc<ProxyManager>,
    client_senders: &ClientSenders,
    stream_waiters: &StreamWaiters,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let first_msg = read_message(&mut reader).await?;

    match first_msg {
        Message::Hello(hello) => {
            handle_control(reader, writer, hello, auth, proxy_manager, client_senders, stream_waiters, shutdown).await
        }
        Message::StreamReady(ready) => {
            info!(stream_id = ready.stream_id, "data stream ready");
            let stream = reader.into_inner().reunite(writer).unwrap();
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
    mut reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    hello: rystra_proto::Hello,
    auth: &TokenAuthPlugin,
    proxy_manager: &Arc<ProxyManager>,
    client_senders: &ClientSenders,
    stream_waiters: &StreamWaiters,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let writer = Arc::new(Mutex::new(writer));
    let mut conn = ControlConnection::new();

    if hello.version != PROTOCOL_VERSION {
        warn!(conn_id = conn.id, "version mismatch");
        return Ok(());
    }

    conn.set_client_id(hello.client_id.clone());
    conn.transition_to(ConnectionState::Authenticating);

    let (tx, mut rx) = mpsc::channel::<Message>(32);
    client_senders.lock().await.insert(hello.client_id.clone(), tx.clone());

    info!(conn_id = conn.id, client_id = %hello.client_id, "control connection, waiting auth");

    let writer_clone = writer.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut w = writer_clone.lock().await;
            if write_message(&mut *w, &msg).await.is_err() {
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
                    info!(conn_id = conn.id, "authenticated");
                } else {
                    warn!(conn_id = conn.id, "auth failed");
                    break;
                }
            }

            Message::RegisterProxy(reg) => {
                if !conn.is_ready() { continue; }
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
                        let (mut ur, mut uw) = user_stream.into_split();
                        let (mut cr, mut cw) = client_stream.into_split();
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