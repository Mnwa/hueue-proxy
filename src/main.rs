extern crate core;

use crate::request::ResponseStatus;
use bytes::BytesMut;
use log::{debug, error, info};
use std::io::Error as IOError;
use std::net::SocketAddr;
use std::str::Utf8Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

mod connect;
mod request;

pub const SOCKS5_VERSION: u8 = 0x05;
pub const ALLOWED_RESERVED: u8 = 0x00;

#[derive(Debug)]
pub enum Socks5Error {
    Parse(IOError),
    InvalidVersion(u8),
    InvalidCommand(u8),
    InvalidReserved(u8),
    Utf8Error(Utf8Error),
}

impl From<IOError> for Socks5Error {
    fn from(e: IOError) -> Self {
        Socks5Error::Parse(e)
    }
}

impl From<Utf8Error> for Socks5Error {
    fn from(e: Utf8Error) -> Self {
        Socks5Error::Utf8Error(e)
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let listening_addr: SocketAddr = match std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:1080".to_string())
        .parse()
    {
        Ok(a) => a,
        Err(e) => {
            error!(target: "init", "{:?}", e);
            return;
        }
    };

    let listener = match make_listener(listening_addr) {
        Ok(l) => l,
        Err(e) => {
            error!(target: "init", "{:?}", e);
            return;
        }
    };

    while let Ok((mut stream, addr)) = listener.accept().await {
        tokio::spawn(async move {
            debug!(target: "connect", "new {}", addr);
            let mut buffer = BytesMut::new();
            if let Err(e) = make_connect(&mut buffer, &mut stream).await {
                error!(target: "connect", "{:?}", e);
                return;
            }

            buffer.clear();

            let mut connect = match handle_request(&mut buffer, &mut stream, listening_addr).await {
                Ok(c) => c,
                Err(e) => {
                    error!(target: "handle", "{:?}", e);
                    return;
                }
            };

            drop(buffer);

            while tokio::io::copy_bidirectional(&mut stream, &mut connect)
                .await
                .is_ok()
            {}
        });
    }
}

fn make_listener(listening_addr: SocketAddr) -> Result<TcpListener, IOError> {
    let socket = match listening_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;

    socket.bind(listening_addr)?;

    socket.listen(1024)
}

async fn make_connect(buffer: &mut BytesMut, stream: &mut TcpStream) -> Result<(), Socks5Error> {
    stream.read_buf(buffer).await?;
    debug!(target: "connect request", "raw {:?}", buffer);
    let request = connect::ConnectRequest::try_from(buffer.as_ref())?;
    info!(target: "connect request", "parsed {:?}", request);
    let response = connect::ConnectResponse::from(request);
    info!(target: "connect response", "parsed {:?}", response);
    let response_buf: Vec<u8> = response.into();
    debug!(target: "connect response", "raw {:?}", response_buf);
    stream.write_all(&response_buf).await?;
    Ok(())
}

async fn handle_request(
    buffer: &mut BytesMut,
    stream: &mut TcpStream,
    listening_addr: SocketAddr,
) -> Result<TcpStream, Socks5Error> {
    stream.read_buf(buffer).await?;
    debug!(target: "handle request", "raw {:?}", buffer);
    let request = request::Request::try_from(buffer.as_ref());
    info!(target: "handle request", "parsed {:?}", request);
    let address_result = request.map_err(ResponseStatus::from).and_then(|r| {
        let status = ResponseStatus::from(r.command);
        if status != ResponseStatus::Success {
            return Err(status);
        }
        Ok(r)
    });

    let address = match address_result {
        Ok(r) => r.address,
        Err(s) => {
            send_response(stream, s, listening_addr).await?;
            return Err(Socks5Error::Parse(std::io::ErrorKind::InvalidData.into()));
        }
    };

    let addresses: Vec<SocketAddr> = address.try_into()?;

    let connection = TcpStream::connect(addresses.as_slice()).await?;

    send_response(stream, ResponseStatus::Success, listening_addr).await?;

    Ok(connection)
}

async fn send_response(
    stream: &mut TcpStream,
    status: ResponseStatus,
    listening_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    let response = request::Response {
        status,
        address: listening_addr.into(),
    };

    info!(target: "handle response", "parsed {:?}", response);
    let response_buf: Vec<u8> = response.try_into()?;
    debug!(target: "handle response", "raw {:?}", response_buf.as_slice());
    stream.write_all(&response_buf).await?;
    Ok(())
}