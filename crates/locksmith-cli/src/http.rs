//! Minimal blocking HTTP/1.1 client over `std::net::TcpStream`.
//!
//! The CLI only talks to a loopback daemon, so this replaces reqwest (and
//! its hyper/rustls/tokio tree) with ~150 lines of std code. One request
//! per call, `Connection: close`, no keep-alive — the CLI is short-lived.
//! HTTPS is deliberately unsupported: the daemon binds loopback HTTP.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Client {
    host: String,
    port: u16,
    timeout: Duration,
}

/// Percent-encode anything outside the unreserved set (RFC 3986).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode a chunked transfer-encoding body.
fn dechunk(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = find_subslice(&body[pos..], b"\r\n")
            .ok_or_else(|| "malformed chunk header".to_string())?
            + pos;
        let size_str = std::str::from_utf8(&body[pos..line_end])
            .map_err(|_| "invalid chunk size".to_string())?;
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| "invalid chunk size".to_string())?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            return Err("truncated chunk".to_string());
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // data + trailing CRLF
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl Client {
    /// `base` is like `http://127.0.0.1:7700`.
    pub fn new(base: &str, timeout: Duration) -> Result<Self, String> {
        let addr = base.strip_prefix("http://").ok_or_else(|| {
            "only http:// endpoints are supported (daemon is loopback HTTP)".to_string()
        })?;
        let (host, port) = match addr.split_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("invalid port in '{base}'"))?,
            ),
            None => (addr.to_string(), 80),
        };
        Ok(Client {
            host,
            port,
            timeout,
        })
    }

    pub fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
        bearer: Option<&str>,
    ) -> Result<(u16, String), String> {
        let mut target = path.to_string();
        if !query.is_empty() {
            let qs: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
                .collect();
            target.push('?');
            target.push_str(&qs.join("&"));
        }
        self.request("GET", &target, None, bearer)
    }

    pub fn post_json(
        &self,
        path: &str,
        body: &str,
        bearer: Option<&str>,
    ) -> Result<(u16, String), String> {
        self.request("POST", path, Some(body), bearer)
    }

    fn request(
        &self,
        method: &str,
        target: &str,
        body: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<(u16, String), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("invalid address '{addr}': {e}"))?,
            self.timeout,
        )
        .map_err(|e| format!("connection failed: {e}"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;

        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAccept: application/json\r\n"
        );
        if let Some(token) = bearer {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(body) = body {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        if let Some(body) = body {
            request.push_str(body);
        }
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("send failed: {e}"))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| format!("read failed: {e}"))?;

        let header_end = find_subslice(&raw, b"\r\n\r\n")
            .ok_or_else(|| "malformed HTTP response".to_string())?;
        let head = std::str::from_utf8(&raw[..header_end])
            .map_err(|_| "invalid response headers".to_string())?;
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| format!("malformed status line '{status_line}'"))?;

        let mut chunked = false;
        for line in lines {
            if line.to_ascii_lowercase().starts_with("transfer-encoding:")
                && line.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }

        let body_bytes = &raw[header_end + 4..];
        let body = if chunked {
            dechunk(body_bytes)?
        } else {
            body_bytes.to_vec()
        };
        let text = String::from_utf8(body).map_err(|_| "response body is not UTF-8".to_string())?;
        Ok((status, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding() {
        assert_eq!(url_encode("file:/src/main.rs"), "file%3A%2Fsrc%2Fmain.rs");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("ok-1_2.3~"), "ok-1_2.3~");
    }

    #[test]
    fn dechunking() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).unwrap(), b"Wikipedia");
    }

    #[test]
    fn client_parses_base() {
        let c = Client::new("http://127.0.0.1:7700", Duration::from_secs(1)).unwrap();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 7700);
        assert!(Client::new("https://example.com", Duration::from_secs(1)).is_err());
    }
}
