extern crate core;

use crate::request::ResponseStatus;
use log::{debug, error, info, warn};
use std::io::{Error as IOError};
use std::net::{ SocketAddr};
use std::str::Utf8Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use crate::init::{Auth, Opts};

mod connect;
mod request;
mod init;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub const SOCKS5_VERSION: u8 = 0x05;
pub const SUB_NEGOTIATION_VERSION: u8 = 0x01;
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
    let Opts { listening_addr, max_pending_connections, allowed_ips, auth } = match Opts::init() {
        Ok(o) => o,
        Err(e) => {
            error!(target: "init", "{:?}", e);
            return;
        }
    };

    let listener = match make_listener(listening_addr, max_pending_connections) {
        Ok(l) => l,
        Err(e) => {
            error!(target: "init", "{:?}", e);
            return;
        }
    };

    while let Ok((mut stream, addr)) = listener.accept().await {
        if matches!(allowed_ips.as_ref(), Some(ips) if !ips.contains(&addr.ip())) {
            warn!(target: "connect", "bad ip {}", addr);
            continue;
        }
        let auth = auth.clone();
        tokio::spawn(async move {
            debug!(target: "connect", "new {}", addr);
            let mut buffer = Vec::new();
            if let Err(e) = make_connect(&mut buffer, &mut stream, auth).await {
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

            info!(target: "connection", "closed {}", addr)
        });
    }
}

fn make_listener(
    listening_addr: SocketAddr,
    max_pending_connections: u32,
) -> Result<TcpListener, IOError> {
    let socket = match listening_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;

    socket.bind(listening_addr)?;

    socket.listen(max_pending_connections)
}

async fn make_connect(
    buffer: &mut Vec<u8>,
    stream: &mut TcpStream,
    auth: Option<Auth>,
) -> Result<(), Socks5Error> {
    stream.read_buf(buffer).await?;
    debug!(target: "connect request", "raw {:?}", buffer);
    let request = connect::ConnectRequest::try_from(buffer.as_ref())?;
    info!(target: "connect request", "parsed {:?}", request);

    let method = request.get_allowed_method(auth.is_some());

    let response = connect::ConnectResponse::from(method);
    info!(target: "connect response", "parsed {:?}", response);
    let response_buf: Vec<u8> = response.into();
    debug!(target: "connect response", "raw {:?}", response_buf);
    stream.write_all(&response_buf).await?;

    if let Some(auth) = auth {
        buffer.clear();
        login(auth, buffer, stream).await?
    }

    Ok(())
}

async fn login(Auth{ user, password }: Auth, buffer: &mut Vec<u8>,
              stream: &mut TcpStream,) -> Result<(), Socks5Error> {
    stream.read_buf(buffer).await?;
    info!(target: "auth request", "accept");
    let request = connect::UserPasswordRequest::try_from(buffer.as_ref())?;
    let response = connect::UserPasswordResponse {
        is_valid: request.is_valid(user, password),
    };
    info!(target: "auth response", "parsed {:?}", response);
    let response_buf: Vec<u8> = response.into();
    debug!(target: "auth response", "raw {:?}", response_buf);
    stream.write_all(&response_buf).await?;
    Ok(())
}

async fn handle_request(
    buffer: &mut Vec<u8>,
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

    let addresses = address.try_into_socket_addresses().await?;

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
