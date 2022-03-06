use crate::{Socks5Error, ALLOWED_RESERVED, SOCKS5_VERSION};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::net::lookup_host;

#[derive(Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub address: ProxyAddress,
}

impl<'a> TryFrom<&'a [u8]> for Request {
    type Error = Socks5Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rdr = Cursor::new(value);
        let version = rdr.read_u8()?;

        if version != SOCKS5_VERSION {
            return Err(Socks5Error::InvalidVersion(version));
        }

        let command: Command = rdr.read_u8()?.try_into()?;

        let reserved = rdr.read_u8()?;
        if reserved != ALLOWED_RESERVED {
            return Err(Socks5Error::InvalidReserved(reserved));
        }

        let address = ProxyAddress::try_from_reader(&mut rdr)?;

        Ok(Self { command, address })
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            c => Err(Socks5Error::InvalidCommand(c)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyAddress {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

impl ProxyAddress {
    pub fn try_from_reader<T: std::io::Read>(rdr: &mut T) -> Result<Self, Socks5Error> {
        let address_type: ProxyAddressType = rdr.read_u8()?.try_into()?;

        let addr = match address_type {
            ProxyAddressType::V4 => {
                let addr = Ipv4Addr::from(rdr.read_u32::<NetworkEndian>()?);
                let port = rdr.read_u16::<NetworkEndian>()?;
                ProxyAddress::V4(SocketAddrV4::new(addr, port))
            }
            ProxyAddressType::V6 => {
                let addr = Ipv6Addr::from(rdr.read_u128::<NetworkEndian>()?);
                let port = rdr.read_u16::<NetworkEndian>()?;
                ProxyAddress::V6(SocketAddrV6::new(addr, port, 0, 0))
            }
            ProxyAddressType::Domain => {
                let octets = rdr.read_u8()? as usize;
                let mut buf = vec![0u8; octets];
                rdr.read_exact(&mut buf)?;

                let domain = std::str::from_utf8(buf.as_slice())?;
                let port = rdr.read_u16::<NetworkEndian>()?;

                ProxyAddress::Domain(domain.to_string(), port)
            }
        };

        Ok(addr)
    }
}

impl TryFrom<ProxyAddress> for Vec<u8> {
    type Error = Socks5Error;

    fn try_from(address: ProxyAddress) -> Result<Self, Self::Error> {
        let mut buf: Vec<u8> = vec![];
        match address {
            ProxyAddress::V4(socket) => {
                buf.write_u8(ProxyAddressType::V4 as u8)?;
                buf.write_u32::<NetworkEndian>(u32::from_be_bytes(socket.ip().octets()))?;
                buf.write_u16::<NetworkEndian>(socket.port())?;
            }
            ProxyAddress::V6(socket) => {
                buf.write_u8(ProxyAddressType::V6 as u8)?;
                buf.write_u128::<NetworkEndian>(u128::from_be_bytes(socket.ip().octets()))?;
                buf.write_u16::<NetworkEndian>(socket.port())?;
            }
            ProxyAddress::Domain(domain, port) => {
                let domain = domain.as_bytes();
                buf.write_u8(ProxyAddressType::Domain as u8)?;
                buf.write_u8(domain.len() as u8)?;
                buf.write_all(domain)?;
                buf.write_u16::<NetworkEndian>(port)?;
            }
        };

        Ok(buf)
    }
}

impl From<SocketAddr> for ProxyAddress {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => ProxyAddress::V4(a),
            SocketAddr::V6(a) => ProxyAddress::V6(a),
        }
    }
}

impl ProxyAddress {
    pub async fn try_into_socket_addresses(&self) -> Result<Vec<SocketAddr>, std::io::Error> {
        match self {
            ProxyAddress::V4(a) => lookup_host(a).await.map(|iter| iter.collect()),
            ProxyAddress::V6(a) => lookup_host(a).await.map(|iter| iter.collect()),
            ProxyAddress::Domain(domain, port) => lookup_host((domain.as_str(), *port))
                .await
                .map(|iter| iter.collect()),
        }
    }
}

pub enum ProxyAddressType {
    V4 = 0x01,
    V6 = 0x04,
    Domain = 0x03,
}

impl TryFrom<u8> for ProxyAddressType {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::V4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::V6),
            c => Err(Socks5Error::InvalidCommand(c)),
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: ResponseStatus,
    pub address: ProxyAddress,
}

impl TryFrom<Response> for Vec<u8> {
    type Error = Socks5Error;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        let mut buf = vec![SOCKS5_VERSION, value.status as u8, ALLOWED_RESERVED];
        let raw_address: Vec<u8> = value.address.try_into()?;
        buf.write_all(raw_address.as_slice())?;
        Ok(buf)
    }
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum ResponseStatus {
    Success = 0x00,
    ServerError = 0x01,
    Forbidden = 0x02,
    NetworkError = 0x03,
    HostError = 0x04,
    ConnectionRestricted = 0x05,
    SessionExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressNotSupported = 0x08,
}

impl From<Command> for ResponseStatus {
    fn from(command: Command) -> Self {
        match command {
            Command::Connect => ResponseStatus::Success,
            Command::Bind => ResponseStatus::CommandNotSupported,
            Command::UdpAssociate => ResponseStatus::CommandNotSupported,
        }
    }
}

impl From<Socks5Error> for ResponseStatus {
    fn from(e: Socks5Error) -> Self {
        match e {
            Socks5Error::Parse(_) => ResponseStatus::ServerError,
            Socks5Error::InvalidVersion(_) => ResponseStatus::ServerError,
            Socks5Error::InvalidCommand(_) => ResponseStatus::CommandNotSupported,
            Socks5Error::InvalidReserved(_) => ResponseStatus::ServerError,
            Socks5Error::Utf8Error(_) => ResponseStatus::AddressNotSupported,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::request::{Command, ProxyAddress, ProxyAddressType, Request, Response};
    use crate::{ResponseStatus, ALLOWED_RESERVED, SOCKS5_VERSION};
    use byteorder::{NetworkEndian, WriteBytesExt};
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_request_connect() {
        let mut raw_request = vec![SOCKS5_VERSION, 0x01, ALLOWED_RESERVED, 0x01];
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;
        raw_request.extend_from_slice(&ip.octets());
        raw_request.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(
            Request::try_from(raw_request.as_slice()).unwrap(),
            Request {
                command: Command::Connect,
                address: ProxyAddress::V4(SocketAddrV4::new(ip, port))
            }
        )
    }

    #[test]
    fn test_response_connect() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;

        let parsed_response = Response {
            status: ResponseStatus::from(Command::Connect),
            address: ProxyAddress::V4(SocketAddrV4::new(ip, port)),
        };

        let mut raw_response = vec![SOCKS5_VERSION, 0x00, ALLOWED_RESERVED, 0x01];
        raw_response.extend_from_slice(&ip.octets());
        raw_response.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(parsed_response).unwrap(), raw_response)
    }

    #[test]
    fn test_request_bind() {
        let mut raw_request = vec![SOCKS5_VERSION, 0x02, ALLOWED_RESERVED, 0x01];
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;
        raw_request.extend_from_slice(&ip.octets());
        raw_request.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(
            Request::try_from(raw_request.as_slice()).unwrap(),
            Request {
                command: Command::Bind,
                address: ProxyAddress::V4(SocketAddrV4::new(ip, port))
            }
        )
    }

    #[test]
    fn test_response_bind() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;

        let parsed_response = Response {
            status: ResponseStatus::from(Command::Bind),
            address: ProxyAddress::V4(SocketAddrV4::new(ip, port)),
        };

        let mut raw_response = vec![SOCKS5_VERSION, 0x07, ALLOWED_RESERVED, 0x01];
        raw_response.extend_from_slice(&ip.octets());
        raw_response.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(parsed_response).unwrap(), raw_response)
    }

    #[test]
    fn test_request_udp() {
        let mut raw_request = vec![SOCKS5_VERSION, 0x03, ALLOWED_RESERVED, 0x01];
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;
        raw_request.extend_from_slice(&ip.octets());
        raw_request.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(
            Request::try_from(raw_request.as_slice()).unwrap(),
            Request {
                command: Command::UdpAssociate,
                address: ProxyAddress::V4(SocketAddrV4::new(ip, port))
            }
        )
    }

    #[test]
    fn test_response_udp() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;

        let parsed_response = Response {
            status: ResponseStatus::from(Command::UdpAssociate),
            address: ProxyAddress::V4(SocketAddrV4::new(ip, port)),
        };

        let mut raw_response = vec![SOCKS5_VERSION, 0x07, ALLOWED_RESERVED, 0x01];
        raw_response.extend_from_slice(&ip.octets());
        raw_response.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(parsed_response).unwrap(), raw_response)
    }

    #[test]
    fn test_proxy_address_v4() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1080;

        let addr = ProxyAddress::V4(SocketAddrV4::new(ip, port));

        let mut raw_addr = vec![ProxyAddressType::V4 as u8];
        raw_addr.extend_from_slice(&ip.octets());
        raw_addr.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(addr.clone()).unwrap(), raw_addr.clone());
        assert_eq!(
            ProxyAddress::try_from_reader(&mut Cursor::new(raw_addr)).unwrap(),
            addr
        )
    }

    #[test]
    fn test_proxy_address_v6() {
        let ip = Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1);
        let port = 1080;

        let addr = ProxyAddress::V6(SocketAddrV6::new(ip, port, 0, 0));

        let mut raw_addr = vec![ProxyAddressType::V6 as u8];
        raw_addr.extend_from_slice(&ip.octets());
        raw_addr.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(addr.clone()).unwrap(), raw_addr.clone());
        assert_eq!(
            ProxyAddress::try_from_reader(&mut Cursor::new(raw_addr)).unwrap(),
            addr
        )
    }

    #[test]
    fn test_proxy_address_domain() {
        let domain = "localhost".to_string();
        let port = 1080;

        let addr = ProxyAddress::Domain(domain.clone(), port);

        let mut raw_addr = vec![
            ProxyAddressType::Domain as u8,
            domain.as_bytes().len() as u8,
        ];
        raw_addr.extend_from_slice(domain.as_bytes());
        raw_addr.write_u16::<NetworkEndian>(port).unwrap();

        assert_eq!(Vec::try_from(addr.clone()).unwrap(), raw_addr.clone());
        assert_eq!(
            ProxyAddress::try_from_reader(&mut Cursor::new(raw_addr)).unwrap(),
            addr
        )
    }
}
