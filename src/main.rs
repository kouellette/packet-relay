use axum::{
    Json, Router,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use pcap::{Active, Capture, Device, Error, Packet, PacketCodec, PacketStream};
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 3000, help = "Port to listen on")]
    port: u16,
}

#[derive(serde::Deserialize)]
struct QueryParams {
    filter: Option<String>,
}

pub struct RawBytesCodec;

impl PacketCodec for RawBytesCodec {
    // A PacketCodec for converting a Packet to Bytes, to be sent via a websocket.
    type Item = Bytes;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        let mut buf = BytesMut::with_capacity(packet.data.len());
        buf.extend_from_slice(packet.data);
        buf.freeze()
    }
}

async fn get_interfaces() -> Result<Json<Vec<String>>, (StatusCode, String)> {
    Ok(Json(
        Device::list()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into_iter()
            .map(|device| device.name)
            .collect(),
    ))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(iface): Path<String>,
    Query(QueryParams { filter }): Query<QueryParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !has_interface(&iface) {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Interface [{}] does not exist", iface),
        ));
    }

    let device = Device::from(iface.as_str());
    let stream = new_stream(device, filter.clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(ws.on_upgrade(move |socket| run_capture_over_ws(socket, stream)))
}

fn has_interface(name: &str) -> bool {
    Device::list()
        .map(|devices| devices.iter().any(|d| d.name == name))
        .unwrap_or(false)
}

fn new_stream(
    device: Device,
    filter: Option<String>,
) -> Result<PacketStream<Active, RawBytesCodec>, Error> {
    let mut cap = Capture::from_device(device.clone())?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    if let Some(filter) = filter {
        info!(
            "Attempting to start capture on interface [{}] with filter [{}]",
            device.name, filter
        );
        cap.filter(&filter, true)?
    } else {
        info!("Attempting to start capture on interface [{}]", device.name);
    }

    cap.stream(RawBytesCodec)
}

async fn run_capture_over_ws(socket: WebSocket, mut stream: PacketStream<Active, RawBytesCodec>) {
    // Split the websocket so we can read control frames while writing
    let (mut ws_tx, mut ws_rx) = socket.split();

    // pcap -> websocket channel
    let (pcap_to_ws_tx, mut pcap_to_ws_rx) = mpsc::channel::<Bytes>(256);

    // websocket -> pcap channel
    let (ws_to_pcap_tx, mut ws_to_pcap_rx) = mpsc::channel::<Bytes>(256);

    // Task 1: Owns the pcap stream. Acts as a bridge between the pcap stream and the websocket.
    let mut reader = tokio::spawn(async move {
        loop {
            tokio::select! {
                recv_packet = stream.next() => {
                    match recv_packet {
                        Some(Ok(bytes)) => {
                            if pcap_to_ws_tx.send(bytes).await.is_err() {
                                break; // writer gone
                            }
                        }
                        Some(Err(_e)) => break,
                        None => break, // end of capture
                    }
                }
                send_packet = ws_to_pcap_rx.recv() => {
                    match send_packet {
                        Some(bytes) => {
                            let _ = stream.capture_mut().sendpacket(bytes);
                        }
                        None => {
                            // control closed; keep reading or decide to exit
                            break;
                        }
                    }
                }
            }
        }
    });

    // Task 2: write messages to websocket (applies backpressure)
    let mut writer = tokio::spawn(async move {
        while let Some(bytes) = pcap_to_ws_rx.recv().await {
            if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                error!("Failed to send packet to websocket");
                break; // client disconnected
            }
        }
    });

    // Task 3: monitor client messages and forward to pcap channel
    let mut control = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Close(_) => {
                    info!("Client disconnected");
                    break;
                }
                Message::Binary(bytes) => {
                    if ws_to_pcap_tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                _ => {}
            }
        }
    });

    // Stop when any task finishes (disconnect, errors, or end-of-stream)
    tokio::select! {
        _ = &mut reader => {
            info!("Packet reader finished. Shutting down channel and websocket");
            writer.abort();
            control.abort();
        }
        _ = &mut writer => {
            info!("Websocket writer finished. Shutting down channel and packet reader");
            reader.abort();
            control.abort();
        }
        _ = &mut control => {
            info!("Websocket receiver finished. Shutting down channel and packet reader");
            reader.abort();
            writer.abort();
        }
    }
}

#[tokio::main{ flavor = "multi_thread" }]
async fn main() {
    // Control log level via RUST_LOG env var. If no value is set, default to info.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_thread_names(true)
        .with_thread_ids(false)
        .with_target(false)
        .init();

    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port);

    let app: Router = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/interfaces", get(get_interfaces))
        .route("/connections/{:iface}", get(ws_handler));

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("Server listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
