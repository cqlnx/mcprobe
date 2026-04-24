use anyhow::{anyhow, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use flate2::read::ZlibDecoder;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io::{self, Write};

// Timeout configs
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

// MC protocol versions we
const MAX_PROTOCOL_VERSION: i32 = 800;
const MIN_PROTOCOL_VERSION: i32 = 47;

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    ip: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    motd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_players: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    online_players: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    players: Option<Vec<Player>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    favicon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_mode: Option<i32>, // -1=unknown, 0=cracked, 1=premium, 2=whitelisted
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Player {
    name: String,
    uuid: String,
}

#[derive(Debug, Deserialize)]
struct ServerResponse {
    #[serde(default)]
    version: Option<VersionInfo>,
    #[serde(default)]
    players: Option<PlayersInfo>,
    #[serde(default)]
    description: Option<serde_json::Value>,
    #[serde(default)]
    favicon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VersionInfo {
    name: String,
    protocol: i32,
}

#[derive(Debug, Deserialize)]
struct PlayersInfo {
    max: i32,
    online: i32,
    #[serde(default)]
    sample: Option<Vec<PlayerSample>>,
}

#[derive(Debug, Deserialize)]
struct PlayerSample {
    name: String,
    id: String,
}

// VarInt stuff - standard MC protocol encoding
fn encode_varint(mut val: i32) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
    buf
}

async fn read_varint(stream: &mut TcpStream) -> Result<i32> {
    let mut result = 0i32;
    let mut shift = 0;
    
    for _i in 0..5 {
        let b = stream.read_u8().await?;
        result |= ((b & 0x7F) as i32) << shift;
        
        if b & 0x80 == 0 {
            return Ok(result);
        }
        
        shift += 7;
    }
    
    Err(anyhow!("VarInt is way too long"))
}

fn encode_string(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut buf = encode_varint(bytes.len() as i32);
    buf.extend_from_slice(bytes);
    buf
}

// Creates the initial handshake packet
fn create_handshake_packet(host: &str, port: u16, next_state: i32, protocol: i32) -> Vec<u8> {
    let mut data = Vec::new();
    
    data.extend_from_slice(&encode_varint(0x00)); // packet id
    data.extend_from_slice(&encode_varint(protocol));
    data.extend_from_slice(&encode_string(host));
    data.extend_from_slice(&port.to_be_bytes());
    data.extend_from_slice(&encode_varint(next_state));
    
    // prepend the length
    let mut packet = encode_varint(data.len() as i32);
    packet.extend_from_slice(&data);
    packet
}

fn create_status_request() -> Vec<u8> {
    vec![0x01, 0x00]
}

// Login packet - has to handle different protocol versions because Mojang
fn create_login_start(username: &str, uuid: &str, protocol: i32) -> Vec<u8> {
    let mut data = Vec::new();
    
    data.extend_from_slice(&encode_varint(0x00)); // login start packet id
    data.extend_from_slice(&encode_string(username));
    
    // Different versions want different data formats
    if protocol >= 47 && protocol <= 758 {
        // 1.8 to 1.18.2 - just username
    } else if protocol == 759 {
        // 1.19 added signature stuff
        data.push(0x00); // no signature data
    } else if protocol == 760 {
        // 1.19.2 - signature + optional uuid
        data.push(0x00); // no sig
        data.push(0x01); // has uuid
        let uuid_bytes = parse_uuid(uuid);
        data.extend_from_slice(&uuid_bytes);
    } else if protocol >= 761 && protocol <= 763 {
        // 1.19.3 to 1.20.1
        data.push(0x01); // has uuid
        let uuid_bytes = parse_uuid(uuid);
        data.extend_from_slice(&uuid_bytes);
    } else if protocol >= 764 {
        // 1.20.2+ always requires uuid
        let uuid_bytes = parse_uuid(uuid);
        data.extend_from_slice(&uuid_bytes);
    }
    
    let mut packet = encode_varint(data.len() as i32);
    packet.extend_from_slice(&data);
    packet
}

fn parse_uuid(uuid: &str) -> Vec<u8> {
    let clean = uuid.replace("-", "");
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or(0))
        .collect()
}

// Parse MOTD - servers can send this in multiple formats
fn parse_motd(desc: &serde_json::Value) -> String {
    match desc {
        serde_json::Value::String(s) => strip_color_codes(s),
        serde_json::Value::Object(obj) => {
            let mut motd = String::new();
            
            if let Some(serde_json::Value::String(text)) = obj.get("text") {
                motd.push_str(&strip_color_codes(text));
            }
            
            if let Some(extra) = obj.get("extra") {
                motd.push_str(&parse_extra(extra));
            }
            
            motd
        }
        serde_json::Value::Array(arr) => {
            arr.iter()
                .filter_map(|v| {
                    if let serde_json::Value::Object(obj) = v {
                        obj.get("text")
                            .and_then(|t| t.as_str())
                            .map(|s| strip_color_codes(s))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        }
        _ => String::new(),
    }
}

fn parse_extra(extra: &serde_json::Value) -> String {
    match extra {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|item| {
                if let serde_json::Value::Object(obj) = item {
                    obj.get("text")
                        .and_then(|t| t.as_str())
                        .map(|s| strip_color_codes(s))
                        .unwrap_or_default()
                } else if let serde_json::Value::String(s) = item {
                    strip_color_codes(s)
                } else {
                    String::new()
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

// Remove minecraft color codes (§c, §l, etc)
fn strip_color_codes(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars();
    
    while let Some(ch) = chars.next() {
        if ch == '§' {
            chars.next(); // skip the color code
        } else {
            result.push(ch);
        }
    }
    
    result
}

// Get basic server info
async fn get_server_status(host: &str, port: u16) -> Result<ServerResponse> {
    let addr_str = format!("{}:{}", host, port);
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(&addr_str)).await??;

    // Handshake (Java)
    let handshake = create_handshake_packet(host, port, 1, 760);
    stream.write_all(&handshake).await?;
    tokio::time::sleep(Duration::from_millis(40)).await;
    
    stream.write_all(&create_status_request()).await?;
    stream.flush().await?;

    timeout(Duration::from_secs(3), async {

        let pkt_len = read_varint(&mut stream).await.map_err(|e| anyhow!("Read pkt len failed: {}", e))?;
        

        if pkt_len < 0 || pkt_len > 65536 {
            return Err(anyhow!("Invalid Java packet length: {} (Likely Bedrock/UDP or Custom Proxy)", pkt_len));
        }

        let pkt_id = read_varint(&mut stream).await?;
        if pkt_id != 0 {
            return Err(anyhow!("Unexpected packet ID: 0x{:02X} (Not a Java Status response)", pkt_id));
        }

        let json_len = read_varint(&mut stream).await?;
        if json_len < 0 || json_len > 65536 {
            return Err(anyhow!("Invalid JSON payload length: {}", json_len));
        }

        let mut json_data = vec![0u8; json_len as usize];
        stream.read_exact(&mut json_data).await?;

        serde_json::from_slice(&json_data).map_err(|e| anyhow!("JSON parse error: {}", e))
    }).await?
}

fn read_varint_slice(data: &[u8], pos: &mut usize) -> Result<i32> {
    let mut result = 0i32;
    let mut shift = 0;
    for _ in 0..5 {
        if *pos >= data.len() {
            return Err(anyhow!("truncated varint"));
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as i32) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(anyhow!("varint too long"))
}

async fn get_auth_mode(host: &str, port: u16, protocol: i32) -> Result<i32> {
    if protocol < MIN_PROTOCOL_VERSION {
        return Ok(-1);
    }

    let addr_str = format!("{}:{}", host, port);
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(&addr_str)).await??;


    let handshake = create_handshake_packet(host, port, 2, protocol);
    stream.write_all(&handshake).await?;
    stream.flush().await?;


    let login = create_login_start("wesdy_qq", "00000000-0000-0000-0000-000000000000", protocol);
    stream.write_all(&login).await?;
    stream.flush().await?;

    let is_modern = protocol >= 764; // 1.20.2+
    let mut compression_threshold: Option<i32> = None;

    timeout(AUTH_TIMEOUT, async {
        loop {

            let pkt_len = read_varint(&mut stream).await?;
            if pkt_len <= 0 { continue; }

            let mut pkt_data = vec![0u8; pkt_len as usize];
            stream.read_exact(&mut pkt_data).await?;

            let mut buffer = if let Some(threshold) = compression_threshold {
                if (pkt_len as i32) > threshold {
                    let mut pos = 0;
                    let data_len = read_varint_from_slice(&pkt_data, &mut pos)?;
                    if data_len == 0 {
                        pkt_data[pos..].to_vec()
                    } else {
                        let mut decoder = ZlibDecoder::new(&pkt_data[pos..]);
                        let mut out = Vec::new();
                        decoder.read_to_end(&mut out)?;
                        out
                    }
                } else {
                    pkt_data
                }
            } else {
                pkt_data
            };

            if buffer.is_empty() { continue; }

            let mut pos = 0;
            let id = read_varint_from_slice(&buffer, &mut pos)?;

            match id {
                //  Encryption Request                 0x01 if !is_modern => return Ok(1),
                0x03 if is_modern  => return Ok(1),

                //  Login Success 
                0x02 if !is_modern => return Ok(0),
                0x00 if is_modern  => return Ok(0),

                //  Disconnect / Kick 
                _ if (id == 0x00 && !is_modern) || (id == 0x01 && is_modern) => {
                    if pos < buffer.len() {
                        let str_len = read_varint_from_slice(&buffer, &mut pos).unwrap_or(0);
                        if str_len > 0 && pos + str_len as usize <= buffer.len() {
                            if let Ok(reason) = std::str::from_utf8(&buffer[pos..pos + str_len as usize]) {
                                if reason.to_lowercase().contains("whitelist") {
                                    return Ok(2);
                                }
                            }
                        }
                    }
                    return Ok(2); // По умолчанию кик = вайтлист/неподходящая версия
                }

                //  Set Compression
                _ if (id == 0x03 && !is_modern) || (id == 0x05 && is_modern) => {
                    compression_threshold = Some(read_varint_from_slice(&buffer, &mut pos)?);
                    continue;
                }

                _ => continue, // Игнорируем плагины, задержки и прочее
            }
        }
    })
    .await
    .unwrap_or(Ok(-1))
}
async fn try_login_probe(host: &str, port: u16, base_protocol: i32) -> Result<ScanResult> {
    let addr_str = format!("{}:{}", host, port);
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(&addr_str)).await??;

    // Handshake в состояние LOGIN (2)
    let handshake = create_handshake_packet(host, port, 2, base_protocol);
    stream.write_all(&handshake).await?;
    tokio::time::sleep(Duration::from_millis(50)).await; // Имитация задержки клиента

    // Login Start
    let login = create_login_start("RealClient", "00000000-0000-0000-0000-000000000000", base_protocol);
    stream.write_all(&login).await?;
    stream.flush().await?;

    // Ждём ответ с таймаутом
    timeout(AUTH_TIMEOUT, async {
        let pkt_len = read_varint(&mut stream).await?;
        if pkt_len <= 0 || pkt_len > 10000 { return Err(anyhow!("invalid pkt len")); }

        let mut pkt_data = vec![0u8; pkt_len as usize];
        stream.read_exact(&mut pkt_data).await?;

        let mut pos = 0;
        let id = read_varint_slice(&pkt_data, &mut pos)?;

        match id {
            0x00 => {
                // Disconnect / Kick
                let mut reason = "Unknown".to_string();
                if pos < pkt_data.len() {
                    let str_len = read_varint_slice(&pkt_data, &mut pos).unwrap_or(0);
                    if str_len > 0 && pos + str_len as usize <= pkt_data.len() {
                        if let Ok(json_str) = std::str::from_utf8(&pkt_data[pos..pos + str_len as usize]) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                                reason = format!("Kick: {}", v.to_string());
                            }
                        }
                    }
                }
                Ok(ScanResult {
                    ip: host.to_string(), port,
                    motd: None, version: Some("Protected/Proxy".to_string()),
                    protocol: Some(base_protocol), max_players: None, online_players: None,
                    players: None, favicon: None, auth_mode: None, error: Some(reason),
                })
            }
            0x01 => {
                Ok(ScanResult {
                    ip: host.to_string(), port,
                    motd: None, version: Some("Online/Protected".to_string()),
                    protocol: Some(base_protocol), max_players: None, online_players: None,
                    players: None, favicon: None, auth_mode: Some(1), error: None,
                })
            }
            0x02 => {
                Ok(ScanResult {
                    ip: host.to_string(), port,
                    motd: None, version: Some("Cracked/Unprotected".to_string()),
                    protocol: Some(base_protocol), max_players: None, online_players: None,
                    players: None, favicon: None, auth_mode: Some(0), error: None,
                })
            }
            _ => Err(anyhow!("Unexpected login packet: 0x{:02X}", id)),
        }
    }).await?
}

async fn scan_server(ip: String, port: u16, check_auth: bool) -> ScanResult {
    let scan_result = timeout(Duration::from_secs(12), async {
        let mut res = ScanResult {
            ip: ip.clone(), port,
            motd: None, version: None, protocol: None,
            max_players: None, online_players: None, players: None,
            favicon: None, auth_mode: None, error: None,
        };

        match get_server_status(&ip, port).await {
            Ok(resp) => {
                if let Some(v) = resp.version { res.version = Some(v.name); res.protocol = Some(v.protocol); }
                if let Some(p) = resp.players {
                    res.max_players = Some(p.max); res.online_players = Some(p.online);
                    if let Some(sample) = p.sample {
                        res.players = Some(sample.into_iter().map(|p| Player { name: p.name, uuid: p.id }).collect());
                    }
                }
                if let Some(d) = resp.description { res.motd = Some(parse_motd(&d)); }
                res.favicon = resp.favicon;
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("not a Minecraft server") || err_msg.contains("strict firewall") || err_msg.contains("timeout") {
                    match try_login_probe(&ip, port, 760).await {
                        Ok(fallback) => return fallback, // Возвращаем результат из Login
                        Err(login_err) => res.error = Some(format!("Status failed, Login also failed: {}", login_err)),
                    }
                } else {
                    res.error = Some(err_msg);
                }
            }
        }

        if check_auth && res.protocol.is_some() && res.error.is_none() {
            let proto = res.protocol.unwrap();
            if proto >= MIN_PROTOCOL_VERSION {
                res.auth_mode = Some(get_auth_mode(&ip, port, proto).await.unwrap_or(-1));
            } else {
                res.auth_mode = Some(-1);
            }
        }
        res
    }).await;

    scan_result.unwrap_or_else(|_| ScanResult {
        ip, port, motd: None, version: None, protocol: None,
        max_players: None, online_players: None, players: None,
        favicon: None, auth_mode: None, error: Some("Global Timeout".to_string()),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let input = tokio::fs::read_to_string("input.txt").await?;
    let lines: Vec<String> = input.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    
    println!("Minecraft Server Scanner");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Found {} servers to scan", lines.len());
    println!();
    
    let check_auth = true;
    let max_concurrent = 10;

    let counter = Arc::new(AtomicUsize::new(0));
    let total = lines.len();

    let sem = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::new();
    
    for line in lines {
        let (ip, port) = match line.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(25565)),
            None => (line.clone(), 25565)
        };
        
        let s = sem.clone();
        let c = counter.clone();
        
        tasks.push(tokio::spawn(async move {
            let _permit = s.acquire().await.unwrap();
            
            let r = scan_server(ip, port, check_auth).await;
            
            let scanned = c.fetch_add(1, Ordering::SeqCst) + 1;

            print!("\rScanned {}/{}", scanned, total);
            io::stdout().flush().unwrap(); 

            r
        }));
    }
    
    let mut results = Vec::new();
    for t in tasks {
        if let Ok(r) = t.await {
            results.push(r);
        }
    }
    
    println!("\nDone!");

    let total = results.len();
    let ok = results.iter().filter(|r| r.error.is_none()).count();
    
    
    tokio::fs::write("results.json", serde_json::to_string_pretty(&results)?).await?;
    
    println!();
    println!("Saved to: results.json");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    Ok(())
}

fn read_varint_from_slice(data: &[u8], pos: &mut usize) -> Result<i32> {
    let mut result = 0i32;
    let mut shift = 0;
    for _ in 0..5 {
        if *pos >= data.len() {
            return Err(anyhow!("unexpected end of data"));
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as i32) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(anyhow!("varint too long"))
}
