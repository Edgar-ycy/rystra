use rystra_auth_token::TokenAuthPlugin;
use rystra_config::ServerConfig;
use rystra_core::{read_message, write_message, ConnectionState, ControlConnection, ProxyEntry, ProxyManager};
use rystra_observe::{error, info, warn};
use rystra_plugin::{AuthPlugin, TransportPlugin, TransportStream};
use rystra_proto::{AuthResponse, Message, OpenStream, RegisterProxyResponse, PROTOCOL_VERSION};
use rystra_transport_tcp::TcpTransportPlugin;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
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
        info!("received shutdown signal, stopping...");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    let transport = TcpTransportPlugin::new();
    let auth = TokenAuthPlugin::with_tokens(vec!["secret-token".to_string()]);
    let proxy_manager = Arc::new(ProxyManager::new());
    let client_senders: ClientSenders = Arc::new(Mutex::new(HashMap::new()));
    let stream_waiters: StreamWaiters = Arc::new(Mutex::new(HashMap::new()));

    let data_addr = format!("{}:{}", config.bind_addr, config.data_port);
    let stream_waiters_clone = stream_waiters.clone();
    let shutdown_data = shutdown.clone();
    tokio::spawn(async move {
        run_data_listener(&data_addr, stream_waiters_clone, shutdown_data).await;
    });

    let addr = format!("{}:{}", config.bind_addr, config.bind_port);
    info!(addr = %addr, "control plane listening");

    let listener = transport.listen(&addr).await.unwrap();

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("server shutting down gracefully");
            break;
        }

        let accept_result = tokio::select! {
            result = listener.accept() => Some(result),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(result) = accept_result {
            match result {
                Ok(stream) => {
                    let auth = auth.clone();
                    let proxy_manager = proxy_manager.clone();
                    let client_senders = client_senders.clone();
                    let stream_waiters = stream_waiters.clone();
                    let data_port = config.data_port;
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &auth, &proxy_manager, &client_senders, &stream_waiters, data_port, shutdown).await {
                            error!(error = %e, "connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept error");
                }
            }
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    info!("server stopped");
}

async fn run_data_listener(addr: &str, stream_waiters: StreamWaiters, shutdown: Arc<AtomicBool>) {
    let listener = TcpListener::bind(addr).await.unwrap();
    info!(addr = %addr, "data plane listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let accept_result = tokio::select! {
            result = listener.accept() => Some(result),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(result) = accept_result {
            match result {
                Ok((stream, addr)) => {
                    info!(addr = %addr, "data connection");
                    let stream_waiters = stream_waiters.clone();
                    tokio::spawn(async move {
                        handle_data_connection(stream, stream_waiters).await;
                    });
                }
                Err(e) => {
                    error!(error = %e, "data accept error");
                }
            }
        }
    }
}

async fn handle_data_connection(mut stream: TcpStream, stream_waiters: StreamWaiters) {
    let mut buf_reader = BufReader::new(&mut stream);
    
    match read_message(&mut buf_reader).await {
        Ok(Message::StreamReady(ready)) => {
            info!(stream_id = ready.stream_id, "stream ready");
            if let Some(tx) = stream_waiters.lock().await.remove(&ready.stream_id) {
                let _ = tx.send(stream);
            }
        }
        Ok(msg) => {
            warn!(?msg, "unexpected data message");
        }
        Err(e) => {
            error!(error = %e, "data read error");
        }
    }
}

async fn handle_connection(
    stream: Box<dyn TransportStream>,
    auth: &TokenAuthPlugin,
    proxy_manager: &Arc<ProxyManager>,
    client_senders: &ClientSenders,
    stream_waiters: &StreamWaiters,
    data_port: u16,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));
    let mut conn = ControlConnection::new();

    let (tx, mut rx) = mpsc::channel::<Message>(32);

    info!(conn_id = conn.id, "new connection");

    let writer_clone = writer.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut w = writer_clone.lock().await;
            if let Err(e) = write_message(&mut *w, &msg).await {
                error!(error = %e, "write error");
                break;
            }
        }
    });

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!(conn_id = conn.id, "shutdown, closing connection");
            break;
        }

        let read_result = tokio::select! {
            result = read_message(&mut reader) => Some(result),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        let msg = match read_result {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                error!(conn_id = conn.id, error = %e, "read error");
                break;
            }
            None => continue,
        };

        info!(conn_id = conn.id, ?msg, "recv");

        match msg {
            Message::Hello(hello) => {
                if hello.version != PROTOCOL_VERSION {
                    warn!(conn_id = conn.id, "version mismatch");
                    break;
                }
                conn.set_client_id(hello.client_id.clone());
                conn.transition_to(ConnectionState::Authenticating);
                client_senders.lock().await.insert(hello.client_id.clone(), tx.clone());
                info!(conn_id = conn.id, client_id = %hello.client_id, "hello, waiting auth");
            }

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
                if !conn.is_ready() {
                    continue;
                }
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
                let proxy_name = reg.name.clone();
                let port = reg.remote_port;
                let shutdown_proxy = shutdown.clone();

                let success = pm.register(entry);
                if success {
                    info!(proxy = %proxy_name, port = port, "proxy registered");
                    tokio::spawn(async move {
                        if let Err(e) = start_proxy_listener(port, proxy_name, client_id, cs, sw, data_port, shutdown_proxy).await {
                            error!(error = %e, "proxy listener error");
                        }
                    });
                }

                let resp = Message::RegisterProxyResponse(RegisterProxyResponse {
                    name: reg.name,
                    success,
                    message: if success { None } else { Some("proxy already exists".to_string()) },
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

    if let Some(client_id) = &conn.client_id {
        client_senders.lock().await.remove(client_id);
        proxy_manager.unregister_by_client(client_id);
    }
    info!(conn_id = conn.id, "connection closed");
    Ok(())
}

async fn start_proxy_listener(
    port: u16,
    proxy_name: String,
    client_id: String,
    client_senders: ClientSenders,
    stream_waiters: StreamWaiters,
    _data_port: u16,
    shutdown: Arc<AtomicBool>,
) -> rystra_model::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(proxy = %proxy_name, addr = %addr, "proxy listening");

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!(proxy = %proxy_name, "proxy listener stopping");
            break;
        }

        let accept_result = tokio::select! {
            result = listener.accept() => Some(result),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
        };

        if let Some(result) = accept_result {
            let (user_stream, user_addr) = result?;
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

                        let u2c = tokio::io::copy(&mut ur, &mut cw);
                        let c2u = tokio::io::copy(&mut cr, &mut uw);

                        let _ = tokio::try_join!(u2c, c2u);
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