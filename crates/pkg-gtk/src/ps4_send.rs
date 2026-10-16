use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PAYLOAD: &[u8] = include_bytes!("../data/dpi-payload/payload.bin");
const MARKER: [u8; 6] = [0xb4; 6];

pub struct PackageInfo<'a> {
    pub name: &'a str,
    pub content_id: &'a str,
    pub category: &'a str,
    pub size: u64,
    pub icon: Option<&'a [u8]>,
}

enum HttpEvent {
    Progress(u64, u64, u64),
    Completed(u64, u64),
    Error(String),
}

pub fn send(
    path: &Path,
    info: PackageInfo<'_>,
    ps4: Ipv4Addr,
    cancelled: Arc<AtomicBool>,
    mut progress: impl FnMut(u64, u64),
) -> Result<(), String> {
    for (label, value, limit) in [
        ("package name", info.name.as_bytes(), 0x259),
        ("content ID", info.content_id.as_bytes(), 0x30),
        ("package category", info.category.as_bytes(), 12),
    ] {
        if value.is_empty() || value.len() > limit {
            return Err(format!("Invalid {label} for installer payload"));
        }
    }
    if info.icon.is_some_and(|icon| icon.len() > u32::MAX as usize) {
        return Err("Package icon is too large for installer payload".into());
    }
    let local =
        local_address(ps4).map_err(|e| format!("Could not determine local address: {e}"))?;
    let callback = TcpListener::bind(SocketAddrV4::new(local, 0)).map_err(|e| e.to_string())?;
    let http = TcpListener::bind(SocketAddrV4::new(local, 0)).map_err(|e| e.to_string())?;
    callback.set_nonblocking(true).map_err(|e| e.to_string())?;
    http.set_nonblocking(true).map_err(|e| e.to_string())?;
    let callback_port = callback.local_addr().map_err(|e| e.to_string())?.port();
    let http_port = http.local_addr().map_err(|e| e.to_string())?.port();
    send_payload(ps4, patched_payload(local, callback_port)?)?;

    let token = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pkg_path = format!("/{token}/package.pkg");
    let manifest_path = format!("/{token}/package.json");
    let pkg_url = format!("http://{local}:{http_port}{pkg_path}");
    let manifest_url = format!("http://{local}:{http_port}{manifest_path}");
    let manifest = Arc::new(format!(
        "{{\"originalFileSize\":{},\"packageDigest\":\"{}\",\"numberOfSplitFiles\":1,\"pieces\":[{{\"url\":\"{}\",\"fileOffset\":0,\"fileSize\":{},\"hashValue\":\"0000000000000000000000000000000000000000\"}}]}}",
        info.size,
        package_digest(path)?,
        pkg_url,
        info.size,
    ).into_bytes());

    let deadline = Instant::now() + Duration::from_secs(15);
    let (events, http_events) = mpsc::channel();
    let mut metadata_sent = false;
    let mut finished = false;
    let mut covered = Vec::new();
    while !finished {
        if cancelled.load(Ordering::Relaxed) {
            return Err("Sending cancelled".into());
        }
        if !metadata_sent && Instant::now() >= deadline {
            return Err("Installer payload did not connect back. Check GoldHEN BinLoader and firewall settings.".into());
        }
        if !metadata_sent {
            match callback.accept() {
                Ok((mut stream, _)) => {
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                    write_metadata(&mut stream, &manifest_url, &info).map_err(|e| e.to_string())?;
                    metadata_sent = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        match http.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10 * 60)))
                    .ok();
                // BGFT can pause while validating package metadata before resuming reads.
                stream
                    .set_write_timeout(Some(Duration::from_secs(10 * 60)))
                    .ok();
                let path = path.to_owned();
                let pkg_path = pkg_path.clone();
                let manifest_path = manifest_path.clone();
                let manifest = manifest.clone();
                let cancelled = cancelled.clone();
                let events = events.clone();
                std::thread::spawn(move || {
                    let result = serve_request(
                        &mut stream,
                        &path,
                        &pkg_path,
                        &manifest_path,
                        &manifest,
                        &cancelled,
                        &mut |start, end, total| {
                            let _ = events.send(HttpEvent::Progress(start, end, total));
                        },
                    );
                    match result {
                        Ok(Some((start, end))) => {
                            let _ = events.send(HttpEvent::Completed(start, end));
                        }
                        Ok(None) => {}
                        Err(e) if http_client_disconnected(&e) => {}
                        Err(e) => {
                            let _ = events.send(HttpEvent::Error(e.to_string()));
                        }
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        for event in http_events.try_iter() {
            finished = handle_http_event(event, &mut covered, info.size, &mut progress)?;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Let BGFT finish consuming the response before asking payload to exit.
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        if let Ok((mut stream, _)) = callback.accept() {
            let _ = stream.write_all(&0u32.to_le_bytes());
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn handle_http_event(
    event: HttpEvent,
    covered: &mut Vec<(u64, u64)>,
    size: u64,
    progress: &mut impl FnMut(u64, u64),
) -> Result<bool, String> {
    match event {
        HttpEvent::Progress(start, end, total) => {
            // Keep bytes from interrupted requests: BGFT can resume without requesting them again.
            add_range(covered, start, end);
            progress(covered.iter().map(|(start, end)| end - start).sum(), total);
        }
        HttpEvent::Completed(start, end) => add_range(covered, start, end),
        HttpEvent::Error(error) => return Err(format!("HTTP transfer failed: {error}")),
    }
    Ok(covered.first().is_some_and(|range| *range == (0, size)))
}

fn http_client_disconnected(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    )
}

fn local_address(ps4: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((ps4, 9))?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() => Ok(ip),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 LAN route to PS4",
        )),
    }
}

fn patched_payload(local: Ipv4Addr, port: u16) -> Result<Vec<u8>, String> {
    let positions: Vec<_> = PAYLOAD
        .windows(MARKER.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == MARKER).then_some(i))
        .collect();
    let [offset] = positions.as_slice() else {
        return Err("Bundled installer payload has an invalid callback marker".into());
    };
    let mut payload = PAYLOAD.to_vec();
    payload[*offset..*offset + 4].copy_from_slice(&local.octets());
    payload[*offset + 4..*offset + 6].copy_from_slice(&port.to_be_bytes());
    Ok(payload)
}

fn send_payload(ps4: Ipv4Addr, payload: Vec<u8>) -> Result<(), String> {
    let mut errors = Vec::new();
    for port in [9090, 9021, 9020] {
        match TcpStream::connect_timeout(
            &SocketAddrV4::new(ps4, port).into(),
            Duration::from_secs(3),
        ) {
            Ok(mut stream) => {
                stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                return stream
                    .write_all(&payload)
                    .map_err(|e| format!("Could not send payload on port {port}: {e}"));
            }
            Err(e) => errors.push(format!("{port}: {e}")),
        }
    }
    Err(format!(
        "Could not reach GoldHEN BinLoader ({})",
        errors.join(", ")
    ))
}

fn write_metadata(stream: &mut TcpStream, url: &str, info: &PackageInfo<'_>) -> io::Result<()> {
    stream.write_all(&1u32.to_le_bytes())?;
    let package_type = format!("PS4{}", info.category.to_uppercase());
    for value in [
        url.as_bytes(),
        info.name.as_bytes(),
        info.content_id.as_bytes(),
        package_type.as_bytes(),
    ] {
        stream.write_all(&(value.len() as u32).to_le_bytes())?;
        stream.write_all(value)?;
    }
    stream.write_all(&info.size.to_le_bytes())?;
    let icon = info.icon.unwrap_or_default();
    stream.write_all(&(icon.len() as u32).to_le_bytes())?;
    stream.write_all(icon)
}

fn package_digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(0xfe0))
        .map_err(|e| e.to_string())?;
    let mut digest = [0; 32];
    file.read_exact(&mut digest)
        .map_err(|e| format!("Could not read PS4 package digest: {e}"))?;
    Ok(digest.iter().map(|b| format!("{b:02X}")).collect())
}

fn serve_request(
    stream: &mut TcpStream,
    file_path: &Path,
    pkg_path: &str,
    manifest_path: &str,
    manifest: &[u8],
    cancelled: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, u64),
) -> io::Result<Option<(u64, u64)>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");
    let mut range = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        if line.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request header too large",
            ));
        }
        if let Some(value) = line
            .strip_prefix("Range:")
            .or_else(|| line.strip_prefix("range:"))
        {
            range = Some(value.trim().to_owned());
        }
    }
    if !matches!(method, "GET" | "HEAD") {
        return write_status(stream, "405 Method Not Allowed", 0).map(|_| None);
    }
    if path == manifest_path {
        write_headers(
            stream,
            "200 OK",
            manifest.len() as u64,
            None,
            "application/json",
        )?;
        if method == "GET" {
            stream.write_all(manifest)?;
        }
        return Ok(None);
    }
    if path != pkg_path {
        return write_status(stream, "404 Not Found", 0).map(|_| None);
    }
    let mut file = File::open(file_path)?;
    let total = file.metadata()?.len();
    let (start, end) = match range {
        Some(value) => match parse_range(&value, total) {
            Some(value) => value,
            None => {
                write!(
                    stream,
                    "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )?;
                return Ok(None);
            }
        },
        None => (0, total.saturating_sub(1)),
    };
    let length = if total == 0 { 0 } else { end - start + 1 };
    let content_range =
        (start != 0 || length != total).then(|| format!("bytes {start}-{end}/{total}"));
    write_headers(
        stream,
        if content_range.is_some() {
            "206 Partial Content"
        } else {
            "200 OK"
        },
        length,
        content_range.as_deref(),
        "application/octet-stream",
    )?;
    if method == "HEAD" {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(start))?;
    let mut remaining = length;
    let mut sent = 0;
    let mut buffer = [0; 64 * 1024];
    while remaining > 0 {
        if cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let chunk = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..chunk])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "package changed during transfer",
            ));
        }
        stream.write_all(&buffer[..read])?;
        remaining -= read as u64;
        sent += read as u64;
        progress(start + sent - read as u64, start + sent, total);
    }
    Ok(Some((start, start + length)))
}

fn add_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    if start == end {
        return;
    }
    ranges.push((start, end));
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges.iter() {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    *ranges = merged;
}

fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') || total == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?.min(total);
        return (suffix > 0).then_some((total - suffix, total - 1));
    }
    let start = start.parse::<u64>().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.is_empty() {
        total - 1
    } else {
        end.parse::<u64>().ok()?.min(total - 1)
    };
    (end >= start).then_some((start, end))
}

fn write_headers(
    stream: &mut TcpStream,
    status: &str,
    length: u64,
    range: Option<&str>,
    content_type: &str,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nContent-Type: {content_type}\r\nAccept-Ranges: bytes\r\nContent-Disposition: attachment; filename=\"app.pkg\"\r\nConnection: close\r\n"
    )?;
    if let Some(range) = range {
        write!(stream, "Content-Range: {range}\r\n")?;
    }
    stream.write_all(b"\r\n")
}

fn write_status(stream: &mut TcpStream, status: &str, length: u64) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some((0, 9)));
        assert_eq!(parse_range("bytes=90-", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(parse_range("bytes=0-1,4-5", 100), None);
    }

    #[test]
    fn merges_completed_http_ranges() {
        let mut ranges = vec![];
        add_range(&mut ranges, 50, 100);
        add_range(&mut ranges, 0, 25);
        add_range(&mut ranges, 20, 60);
        assert_eq!(ranges, [(0, 100)]);
    }

    #[test]
    fn resumed_transfer_finishes_after_downloader_disconnect() {
        let mut covered = vec![];
        let mut sample = (0, 0);
        // The first request delivered bytes before disconnecting, so it has no Completed event.
        let mut finished = false;
        for event in [
            HttpEvent::Progress(0, 50, 100),
            HttpEvent::Progress(50, 100, 100),
            HttpEvent::Completed(50, 100),
        ] {
            finished = handle_http_event(event, &mut covered, 100, &mut |n, t| {
                sample = (n, t);
            })
            .unwrap();
        }
        assert_eq!(sample, (100, 100));
        assert!(finished, "transfer reached 100% but never completed");
    }

    #[test]
    fn progress_counts_unique_bytes_not_range_end() {
        let mut covered = vec![];
        let mut sample = (0, 0);
        for event in [
            HttpEvent::Progress(50, 100, 100),
            HttpEvent::Progress(75, 100, 100),
            HttpEvent::Completed(50, 100),
        ] {
            assert!(
                !handle_http_event(event, &mut covered, 100, &mut |n, t| {
                    sample = (n, t);
                })
                .unwrap()
            );
        }
        assert_eq!(sample, (50, 100));
    }

    #[test]
    fn downloader_disconnects_are_recoverable() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
        ] {
            assert!(http_client_disconnected(&io::Error::from(kind)));
        }
        assert!(!http_client_disconnected(&io::Error::from(
            io::ErrorKind::InvalidData
        )));
    }

    #[test]
    fn payload_has_one_callback_marker() {
        assert_eq!(
            PAYLOAD
                .windows(MARKER.len())
                .filter(|bytes| *bytes == MARKER)
                .count(),
            1
        );
    }
}
