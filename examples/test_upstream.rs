//! Tiny Rust-only HTTP fixture for the Quantum Shield local proxy smoke test.
//! This is an example, not part of the `qsctl` application binary.

use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const BODY: &[u8] = b"Quantum Shield Rust test upstream\n";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = "127.0.0.1:3000";
    let listener = TcpListener::bind(address).await?;
    println!("Rust test upstream listening only on http://{address}");
    println!("Press Ctrl+C to stop.");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut request = [0_u8; 8192];
            if stream.read(&mut request).await.is_err() {
                return;
            }

            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                BODY.len()
            );
            if stream.write_all(headers.as_bytes()).await.is_err() {
                return;
            }
            if stream.write_all(BODY).await.is_err() {
                return;
            }
            let _ = stream.shutdown().await;
            println!("served local smoke-test request from {peer}");
        });
    }
}
