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

// Timeout configs - feel free to adjust these
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

// MC protocol versions we support
const PROTOCOL_VERSION: i32 = 763; // 1.20.1
const MAX_PROTOCOL_VERSION: i32 = 800;
const MIN_PROTOCOL_VERSION: i32 = 47; // Anything older than 1.8 is pretty rare

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
    
    for i in 0..5 {
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
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr)).await??;
    
    // Send handshake with high protocol so server tells us its real version
    let handshake = create_handshake_packet(host, port, 1, MAX_PROTOCOL_VERSION);
    stream.write_all(&handshake).await?;
    stream.flush().await?;
    
    // Ask for status
    let status_req = create_status_request();
    stream.write_all(&status_req).await?;
    stream.flush().await?;
    
    // Read the response
    let _pkt_len = read_varint(&mut stream).await?;
    let _pkt_id = read_varint(&mut stream).await?;
    let json_len = read_varint(&mut stream).await?;
    
    let mut json_data = vec![0u8; json_len as usize];
    stream.read_exact(&mut json_data).await?;
    
    let response: ServerResponse = serde_json::from_slice(&json_data)?;
    Ok(response)
}

async fn get_auth_mode(host: &str, port: u16, protocol: i32) -> Result<i32> {
    if protocol < MIN_PROTOCOL_VERSION {
        return Err(anyhow!("Protocol {} is too old, can't check", protocol));
    }
    
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let mut stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr)).await??;
    
    let handshake = create_handshake_packet(host, port, 2, protocol);
    stream.write_all(&handshake).await?;
    stream.flush().await?;
    
    let login = create_login_start("popiiumaa", "00000000-0000-0000-0000-000000000000", protocol);
    stream.write_all(&login).await?;
    stream.flush().await?;
    
    let mut compression = -1;
    
    let result = timeout(AUTH_TIMEOUT, async {
        loop {
            let pkt_len = read_varint(&mut stream).await?;
            if pkt_len <= 0 { continue; }
            
            let mut pkt_data = vec![0u8; pkt_len as usize];
            stream.read_exact(&mut pkt_data).await?;
            
            let pkt_bytes = if compression >= 0 {
                let mut pos = 0;
                let mut dlen = 0i32;
                let mut bits = 0;
                
                for _ in 0..5 {
                    if pos >= pkt_data.len() {
                        return Err(anyhow!("bad compressed packet"));
                    }
                    let b = pkt_data[pos];
                    pos += 1;
                    dlen |= ((b & 0x7F) as i32) << bits;
                    if b & 0x80 == 0 { break; }
                    bits += 7;
                }
                
                if dlen == 0 {
                    pkt_data[pos..].to_vec()
                } else {
                    let mut decoder = ZlibDecoder::new(&pkt_data[pos..]);
                    let mut out = Vec::new();
                    decoder.read_to_end(&mut out)?;
                    out
                }
            } else {
                pkt_data
            };
            
            if pkt_bytes.is_empty() { continue; }
            
            let mut pos = 0;
            let mut id = 0i32;
            let mut bits = 0;
            
            for _ in 0..5 {
                if pos >= pkt_bytes.len() { 
                    return Err(anyhow!("bad packet"));
                }
                let b = pkt_bytes[pos];
                pos += 1;
                id |= ((b & 0x7F) as i32) << bits;
                if b & 0x80 == 0 { break; }
                bits += 7;
            }
            
            match id {
                0x00 => {
                    // kick/disconnect
                    if pos < pkt_bytes.len() {
                        let mut slen = 0i32;
                        let mut bits = 0;
                        for _ in 0..5 {
                            if pos >= pkt_bytes.len() { break; }
                            let b = pkt_bytes[pos];
                            pos += 1;
                            slen |= ((b & 0x7F) as i32) << bits;
                            if b & 0x80 == 0 { break; }
                            bits += 7;
                        }
                        
                        if slen > 0 && pos + slen as usize <= pkt_bytes.len() {
                            if let Ok(msg) = std::str::from_utf8(&pkt_bytes[pos..pos + slen as usize]) {
                                if msg.to_lowercase().contains("whitelist") {
                                    return Ok(2);
                                }
                            }
                        }
                    }
                    return Ok(2);
                }
                0x01 => return Ok(1), // encryption = online
                0x02 => return Ok(0), // success = cracked
                0x03 => {
                    // compression enabled
                    let mut thresh = 0i32;
                    let mut bits = 0;
                    for _ in 0..5 {
                        if pos >= pkt_bytes.len() { break; }
                        let b = pkt_bytes[pos];
                        pos += 1;
                        thresh |= ((b & 0x7F) as i32) << bits;
                        if b & 0x80 == 0 { break; }
                        bits += 7;
                    }
                    compression = thresh;
                }
                _ => {} // ignore other packets
            }
        }
    })
    .await;
    
    match result {
        Ok(m) => m,
        Err(_) => Ok(-1),
    }
}

async fn scan_server(ip: String, port: u16, check_auth: bool) -> ScanResult {
    let scan_result = timeout(Duration::from_secs(10), async {
        let mut res = ScanResult {
            ip: ip.clone(),
            port,
            motd: None,
            version: None,
            protocol: None,
            max_players: None,
            online_players: None,
            players: None,
            favicon: None,
            auth_mode: None,
            error: None,
        };
        
        match get_server_status(&ip, port).await {
            Ok(resp) => {
                if let Some(v) = resp.version {
                    res.version = Some(v.name);
                    res.protocol = Some(v.protocol);
                }
                
                if let Some(p) = resp.players {
                    res.max_players = Some(p.max);
                    res.online_players = Some(p.online);
                    
                    if let Some(sample) = p.sample {
                        res.players = Some(
                            sample.into_iter()
                                .map(|p| Player { name: p.name, uuid: p.id })
                                .collect()
                        );
                    }
                }
                
                if let Some(d) = resp.description {
                    res.motd = Some(parse_motd(&d));
                }
                
                res.favicon = resp.favicon;
                
                if check_auth && res.protocol.is_some() {
                    let proto = res.protocol.unwrap();
                    if proto >= MIN_PROTOCOL_VERSION {
                        res.auth_mode = Some(get_auth_mode(&ip, port, proto).await.unwrap_or(-1));
                    } else {
                        res.auth_mode = Some(-1);
                    }
                }
            }
            Err(e) => res.error = Some(e.to_string()),
        }
        res
    }).await;
    
    scan_result.unwrap_or_else(|_| ScanResult {
        ip, port,
        motd: None, version: None, protocol: None,
        max_players: None, online_players: None, players: None,
        favicon: None, auth_mode: None,
        error: Some("Timeout".to_string()),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let input = tokio::fs::read_to_string("input.txt").await?;
    let lines: Vec<String> = input.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    
    println!("🔍 Minecraft Server Scanner");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Found {} servers to scan", lines.len());
    println!();
    
    let check_auth = false;
    let max_concurrent = 500;
    
    let mp = MultiProgress::new();
    let pb = mp.add(ProgressBar::new(lines.len() as u64));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}").unwrap()
        .progress_chars("█▓▒░"));
    
    let status = mp.add(ProgressBar::new(0));
    status.set_style(ProgressStyle::default_bar().template("   ✓ {msg}").unwrap());
    
    let sem = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::new();
    
    for line in lines {
        let (ip, port) = match line.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(25565)),
            None => (line.clone(), 25565)
        };
        
        let s = sem.clone();
        let p = pb.clone();
        let st = status.clone();
        
        tasks.push(tokio::spawn(async move {
            let _permit = s.acquire().await.unwrap();
            let r = scan_server(ip.clone(), port, check_auth).await;
            p.inc(1);
            
            if r.error.is_none() && r.version.is_some() {
                st.set_message(format!("Success: {} | {} | Players: {}/{}",
                    ip, r.version.as_ref().unwrap(),
                    r.online_players.unwrap_or(0), r.max_players.unwrap_or(0)));
            }
            r
        }));
    }
    
    let mut results = Vec::new();
    for t in tasks {
        if let Ok(r) = t.await { results.push(r); }
    }
    
    pb.finish_with_message("Done!");
    status.finish_and_clear();
    
    let total = results.len();
    let ok = results.iter().filter(|r| r.error.is_none()).count();
    let online = results.iter().filter(|r| r.auth_mode == Some(1)).count();
    let cracked = results.iter().filter(|r| r.auth_mode == Some(0)).count();
    let wl = results.iter().filter(|r| r.auth_mode == Some(2)).count();
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📈 Results:");
    println!("   Total:      {}", total);
    println!("   ✓ Success:  {} ({:.1}%)", ok, (ok as f32 / total as f32) * 100.0);
    println!("   ✗ Failed:   {} ({:.1}%)", total - ok, ((total - ok) as f32 / total as f32) * 100.0);
    
    if check_auth {
        println!();
        println!("🔐 Auth:");
        println!("   🟢 Online:    {}", online);
        println!("   🟡 Cracked:   {}", cracked);
        println!("   🔴 Whitelist: {}", wl);
    }
    
    tokio::fs::write("results.json", serde_json::to_string_pretty(&results)?).await?;
    
    println!();
    println!("💾 Saved to: results.json");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    Ok(())
}
